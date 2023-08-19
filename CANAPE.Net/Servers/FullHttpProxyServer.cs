//    CANAPE Core Network Testing Library
//    Copyright (C) 2017 James Forshaw
//    Based in part on CANAPE Network Testing Tool
//    Copyright (C) 2014 Context Information Security
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.
using CANAPE.DataAdapters;
using CANAPE.DataFrames;
using CANAPE.Net.Clients;
using CANAPE.Net.Layers;
using CANAPE.Net.Protocols.Parser;
using CANAPE.Net.Tokens;
using CANAPE.Net.Utils;
using CANAPE.NodeFactories;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace CANAPE.Net.Servers
{
    // Implementation of full HTTP proxy
    // To do this successfully requires chaining two servers together
    // The first server is just the connection made to the proxy, it acts to parse HTTP requests into an appropriate form
    // If the connection being made is a CONNECT then it just will fall back to old style legacy mode and open the standard client outbound
    // If connection is not CONNECT then parse out initial headers, then create a special client which actually feeds back into itself
    // Connections could be pooled or not

    /// <summary>
    /// Full HTTP proxy server implementation    
    /// </summary>
    public class FullHttpProxyServer : ProxyServer
    {
        private const string DATA_NAME = "Data";

        HttpProxyServerConfig _config;
        NetGraphFactory _factory;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="logger">The logger</param>
        /// <param name="config">Configuration for the server</param>
        public FullHttpProxyServer(HttpProxyServerConfig config, Logger logger)
            : base(logger)
        {
            _config = config;

            NetGraphBuilder builder = new NetGraphBuilder();

            ClientEndpointFactory client = builder.AddClient("Client", Guid.NewGuid());
            ServerEndpointFactory server = builder.AddServer("Server", Guid.NewGuid());

            DirectNodeFactory nop = builder.AddNode(new DirectNodeFactory("NOP", Guid.NewGuid()));

            builder.AddLines(client, nop, server, client);

            _factory = builder.Factory;
        }

        /// <summary>
        /// Just a defined type so the service can recognize it coming through
        /// </summary>
        private class HttpProxyDataAdapter : CoupledDataAdapter
        {
            public HttpProxyDataAdapter(Uri url, CancellationToken token)
                : base(token)
            {
                Url = url;
                Description = "HTTP Proxy Server";
            }

            public Uri Url { get; private set; }
        }

        private class HttpProxyClientDataAdapter : EnumerableDataAdapter
        {
            class ProxyConnection
            {
                public NetGraph Graph { get; set; }
                public HttpProxyDataAdapter DataAdapter { get; set; }
                public IEnumerable<HttpResponseDataChunk> ResponseReader { get; set; }
            }

            FullHttpProxyServer _server;
            LockedQueue<ProxyConnection> _conns;
            List<NetGraph> _graphs;
            Logger _logger;
            CancellationTokenSource _cancellationSource;
            ProxyNetworkService _service;
            ProxyConnection _currOutConn = null;

            public HttpProxyClientDataAdapter(FullHttpProxyServer server, ProxyNetworkService service, Logger logger)
            {
                _server = server;
                _service = service;
                _cancellationSource = new CancellationTokenSource();
                _conns = new LockedQueue<ProxyConnection>(-1, _cancellationSource.Token);
                _logger = logger;
                _graphs = new List<NetGraph>();
                Description = "HTTP Proxy Server";
            }

            private HttpResponseDataChunk BuildError(int error, string message, string method, HttpVersion version)
            {
                HttpResponseDataChunk response = new HttpResponseDataChunk();

                response.Version = version;
                response.ResponseCode = error;
                response.Message = message;
                response.FinalChunk = true;
                response.Body = new byte[0];

                List<HttpHeader> headers = new List<HttpHeader>();

                headers.Add(new HttpHeader("X-Proxy-Server", "CANAPE"));
                response.Headers = headers.ToArray();

                if (method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
                {
                    response.HeadResponse = true;
                }
                else if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
                {
                    response.ConnectResponse = true;
                }

                return response;
            }

            private IEnumerable<HttpResponseDataChunk> GetResponse(ProxyConnection conn, Uri url, bool headRequest)
            {
                try
                {
                    DataReader reader = new DataReader(conn.DataAdapter.Coupling);

                    HttpParserConfig config = new HttpParserConfig();
                    config.StreamBody = true;

                    if (_server._config.Version10Proxy)
                    {
                        config.DowngradeChunkedToHttp10 = true;
                    }

                    _logger.LogVerbose("Starting processing of {0}", url);

                    HttpResponseHeader response = HttpParser.ReadResponseHeader(reader, false, _logger);

                    // If 100 continue then read out just that response then restart read
                    if (response.Is100Continue)
                    {
                        foreach (HttpResponseDataChunk chunk in response.ReadChunks(config))
                        {
                            _logger.LogVerbose("Read 100 continue chunk for {0} {1} {2}", url, chunk.Body.Length, chunk.FinalChunk);

                            yield return chunk;
                        }

                        response = HttpParser.ReadResponseHeader(reader, false, _logger);
                    }

                    _logger.LogVerbose("Read response header {0}", response.ResponseCode);

                    response.SetHeadRequest(headRequest);

                    foreach (HttpResponseDataChunk newChunk in response.ReadChunks(config))
                    {
                        _logger.LogVerbose("Read chunk for {0} {1} {2}", url, newChunk.Body.Length, newChunk.FinalChunk);

                        yield return newChunk;
                    }
                }
                finally
                {
                    bool closeSuccess = false;
                    try
                    {
                        conn.DataAdapter.Coupling.Dispose();
                        lock (_graphs)
                        {
                            _graphs.Remove(conn.Graph);
                        }
                        closeSuccess = true;
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (ObjectDisposedException)
                    {
                    }

                    if (!closeSuccess)
                    {
                        lock (_graphs)
                        {
                            // Force close
                            _service.CloseConnection(conn.Graph);
                            _graphs.Remove(conn.Graph);
                        }
                    }
                }
            }

            protected override IEnumerable<DataFrame> GetFrames()
            {
                ProxyConnection conn = _conns.Dequeue();

                while (conn != null)
                {
                    bool receivedFinal = false;

                    foreach (HttpResponseDataChunk chunk in conn.ResponseReader)
                    {
                        receivedFinal = chunk.FinalChunk;
                        yield return chunk.ToDataFrame();
                    }

                    // If we didn't receive final chunk we have an error, start shutdown
                    if (!receivedFinal)
                    {
                        _conns.Stop();
                        break;
                    }

                    conn = _conns.Dequeue();
                }

                lock (_graphs)
                {
                    foreach (NetGraph graph in _graphs)
                    {
                        _service.CloseConnection(graph);
                    }
                }
            }

            private NetGraph ConnectClient(IDataAdapter adapter)
            {
                PropertyBag bag = new PropertyBag("Server");
                NetGraph graph = null;

                for (int i = 0; i < _server._config.ConnectionRetries; ++i)
                {
                    graph = _service.ConnectClient(adapter, bag);
                    if (graph != null)
                    {
                        lock (_graphs)
                        {
                            _graphs.Add(graph);
                        }

                        break;
                    }
                }

                return graph;
            }

            /// <summary>
            /// Write the specified frame.
            /// </summary>
            /// <param name="frame">The frame to write.</param>
            public override void Write(DataFrame frame)
            {
                Uri currUri = null;
                var chunk = frame.GetValue<HttpRequestDataChunk>().Clone();

                if (chunk.ChunkNumber == 0)
                {
                    int error = 0;
                    string message = null;

                    if (_currOutConn == null)
                    {
                        try
                        {
                            _logger.LogVerbose("Received new connection to {0}", chunk.Path);

                            currUri = new Uri(chunk.Path, UriKind.Absolute);

                            chunk.Path = currUri.PathAndQuery;

                            // Upgrade to at least version 1.0
                            if (chunk.Version.IsVersionUnknown)
                            {
                                chunk.Version = HttpVersion.Version10;
                            }

                            // Add a Connection: close header?
                            _currOutConn = new ProxyConnection();
                            _currOutConn.DataAdapter = new HttpProxyDataAdapter(currUri, _cancellationSource.Token);

                            _currOutConn.Graph = ConnectClient(_currOutConn.DataAdapter);
                            if (_currOutConn.Graph == null)
                            {
                                _currOutConn.DataAdapter.Dispose();
                                error = 404;
                                message = "Not Found";
                                _currOutConn = null;
                            }
                            else
                            {
                                _currOutConn.ResponseReader = GetResponse(_currOutConn,
                                              currUri, chunk.Method.Equals("HEAD", StringComparison.OrdinalIgnoreCase));
                                _conns.Enqueue(_currOutConn);
                            }
                        }
                        catch (UriFormatException)
                        {
                            error = 400;
                            message = "Bad Request";
                        }

                        if (error != 0)
                        {
                            ProxyConnection conn = new ProxyConnection();

                            conn.ResponseReader = new[] { BuildError(error, message, chunk.Method, chunk.Version) };
                            _conns.Enqueue(conn);
                        }
                    }
                }

                if (_currOutConn != null)
                {
                    DataWriter writer = new DataWriter(new DataAdapterToStream(_currOutConn.DataAdapter.Coupling));

                    chunk.WriteChunk(writer);

                    if (chunk.FinalChunk)
                    {
                        _currOutConn = null;
                    }
                }
                else
                {
                    // Do nothing
                }
            }

            protected override void OnDispose(bool disposing)
            {
                _conns.Stop();
                lock (_graphs)
                {
                    // If there are still pending connections to flush out we are in error, shutdown quickly
                    if (_graphs.Count > 0)
                    {
                        _cancellationSource.Cancel();
                    }
                }
            }
        }

        private class HttpProxyDummyClient : ProxyClient
        {
            private FullHttpProxyServer _server;
            private ProxyNetworkService _service;

            public override IDataAdapter Connect(ProxyToken token, Logger logger, MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
            {
                return new HttpProxyClientDataAdapter(_server, _service, _server._logger);
            }

            public HttpProxyDummyClient(FullHttpProxyServer server, ProxyNetworkService service)
            {
                _server = server;
                _service = service;
            }

            public override IDataAdapter Bind(ProxyToken token, Logger logger, MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
            {
                return null;
            }
        }

        private class HttpProxyServerAdapter : BaseDataAdapter
        {
            private DataAdapterToStream _stm;
            private DataWriter _writer;
            private HttpRequestHeader _request;
            private IEnumerator<HttpRequestDataChunk> _chunks;
            private HttpParserConfig _config;
            private Logger _logger;
            private bool _closeConnection;
            private Queue<HttpRequestHeader> _requestQueue;
            private FullHttpProxyServer _server;
            private bool _removeChunked;

            public HttpProxyServerAdapter(FullHttpProxyServer server, DataAdapterToStream stm, HttpRequestHeader initialRequest, Logger logger)
            {
                _server = server;
                _stm = stm;
                _writer = new DataWriter(_stm);
                _request = initialRequest;
                ProcessProxyRequestHeaders(_request);
                _config = new HttpParserConfig();
                _config.StreamBody = true;
                _logger = logger;
                _requestQueue = new Queue<HttpRequestHeader>();
                _requestQueue.Enqueue(_request);

                Description = stm.Description;
            }

            private void ProcessProxyRequestHeaders(HttpRequestHeader request)
            {
                int i = 0;

                // If we have a request for a client version which will close then ensure the job is done 
                if (request.Version.IsVersionUnknown || request.Version.IsVersion10 || _server._config.Version10Proxy)
                {
                    _closeConnection = true;
                }

                while (i < request.Headers.Count)
                {
                    HttpHeader pair = request.Headers[i];

                    // Just remove, we already have handled this
                    if (pair.Name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase))
                    {
                        request.Headers.RemoveAt(i);
                    }
                    else if (pair.Name.Equals("Connection", StringComparison.OrdinalIgnoreCase)
                        || pair.Name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase))
                    {
                        // If sender wants the connection close then signal it for next response
                        if (pair.Value.Equals("close", StringComparison.OrdinalIgnoreCase))
                        {
                            _closeConnection = true;
                        }

                        request.Headers.RemoveAt(i);
                    }
                    else
                    {
                        ++i;
                    }
                }
            }

            private void ProcessProxyResponseHeaders(HttpResponseDataChunk response)
            {
                List<HttpHeader> headers = new List<HttpHeader>(response.Headers);

                int i = 0;

                while (i < headers.Count)
                {
                    HttpHeader pair = headers[i];

                    // We don't send connection headers
                    if (pair.Name.Equals("Connection", StringComparison.OrdinalIgnoreCase) || pair.Name.Equals("Proxy-Connection"))
                    {
                        headers.RemoveAt(i);
                    }
                    else
                    {
                        ++i;
                    }
                }
            }

            public override DataFrame Read()
            {
                try
                {
                    if (_request == null)
                    {
                        _request = HttpParser.ReadRequestHeader(new DataReader(_stm), false, _logger);

                        lock (_requestQueue)
                        {
                            _requestQueue.Enqueue(_request);
                        }

                        ProcessProxyRequestHeaders(_request);
                    }

                    if (_chunks == null)
                    {
                        _chunks = _request.ReadChunks(_config).GetEnumerator();

                        // If we can't move to the first chunk (headers) there is a serious issue
                        if (!_chunks.MoveNext())
                        {
                            throw new EndOfStreamException();
                        }
                    }

                    HttpRequestDataChunk chunk = _chunks.Current;

                    if (!_chunks.MoveNext())
                    {
                        _request = null;
                        _chunks = null;
                    }

                    return chunk.ToDataFrame();
                }
                catch (EndOfStreamException)
                {
                    return null;
                }
            }

            private void Write(HttpResponseDataChunk chunk)
            {
                // Add proxy specific headers
                if (chunk.ChunkNumber == 0)
                {
                    ProcessProxyResponseHeaders(chunk);
                    lock (_requestQueue)
                    {
                        HttpRequestHeader request = _requestQueue.Dequeue();

                        // Fix up version to match the request
                        if (_server._config.Version10Proxy && !request.Version.IsVersionUnknown)
                        {
                            chunk.Version = HttpVersion.Version10;
                        }
                        else
                        {
                            chunk.Version = request.Version;
                        }

                        if (!chunk.Version.IsVersion11)
                        {
                            // Remove chunked encoding for sending back 1.0                            
                            _removeChunked = true;
                            _closeConnection = true;
                        }
                        else
                        {
                            // If not chunk encoding and no content-length then set close of end
                            if (!chunk.ChunkedEncoding)
                            {
                                bool hasContentLength = false;

                                foreach (HttpHeader header in chunk.Headers)
                                {
                                    if (header.Name.Equals("content-length", StringComparison.OrdinalIgnoreCase))
                                    {
                                        hasContentLength = true;
                                        break;
                                    }
                                }

                                if (!hasContentLength)
                                {
                                    List<HttpHeader> headers = new List<HttpHeader>(chunk.Headers);
                                    headers.Add(new HttpHeader("Connection", "close"));
                                    chunk.Headers = headers.ToArray();
                                    _closeConnection = true;
                                }
                            }
                        }
                    }
                }

                if (_removeChunked)
                {
                    chunk.ChunkedEncoding = false;
                }

                chunk.WriteChunk(_writer);

                if (chunk.FinalChunk)
                {
                    if (_closeConnection)
                    {
                        Dispose();
                    }
                }
            }

            public override void Write(DataFrame frame)
            {
                var chunk = frame.GetValue<HttpResponseDataChunk>();

                Write(chunk);
            }

            protected override void OnDispose(bool disposing)
            {
                _stm.Dispose();
            }

            public override bool CanTimeout
            {
                get
                {
                    return _stm.CanTimeout;
                }
            }

            public override int ReadTimeout
            {
                get
                {
                    return _stm.ReadTimeout;
                }
                set
                {
                    _stm.ReadTimeout = value;
                }
            }
        }

        private void ReturnResponse(HttpRequestHeader request, int responseCode, string message, string method, HttpVersion version, DataAdapterToStream stm)
        {
            ReturnResponse(request, responseCode, message, method, version, new HttpHeader[0], stm);
        }

        private void ReturnResponse(HttpRequestHeader request, int responseCode, string message, string method, HttpVersion version, IEnumerable<HttpHeader> sendHeaders, DataAdapterToStream stm)
        {
            if (request != null)
            {
                FlushRequest(request);
            }

            HttpResponseDataChunk response = new HttpResponseDataChunk();

            if (_config.Version10Proxy && !version.IsVersionUnknown)
            {
                response.Version = HttpVersion.Version10;
            }
            else
            {
                response.Version = version;
            }

            response.ResponseCode = responseCode;
            response.Message = message;
            response.FinalChunk = true;
            response.Body = new byte[0];

            List<HttpHeader> headers = new List<HttpHeader>(sendHeaders);

            headers.Add(new HttpHeader("X-Proxy-Server", "CANAPE"));

            if (response.Body.Length > 0)
            {
                headers.Add(new HttpHeader("Content-Type", "text/html"));
            }

            response.Headers = headers.ToArray();

            if (method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
            {
                response.HeadResponse = true;
            }
            else if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                response.ConnectResponse = true;
            }

            response.WriteChunk(new DataWriter(stm));
        }

        private IpProxyToken HandleConnect(HttpRequestHeader header, DataAdapterToStream stm)
        {
            string hostName = null;
            int port = 80;
            string[] connectHeader = header.Path.Split(':');
            IpProxyToken ret = null;

            if (connectHeader.Length > 0)
            {
                hostName = connectHeader[0];
                if (connectHeader.Length > 1)
                {
                    if (!int.TryParse(connectHeader[1], out port))
                    {
                        _logger.LogError(CANAPE.Net.Properties.Resources.HttpProxyServer_InvalidConnect, connectHeader[1]);
                        port = 0;
                    }
                }

                if (port > 0)
                {
                    ret = new IpProxyToken(null, hostName, port, IpProxyToken.IpClientType.Tcp, false);

                    ret.State.Add("stm", stm);
                    ret.State.Add("header", header);
                }
                else
                {
                    ReturnResponse(null, 400, "Bad Request", header.Method, header.Version, stm);
                }
            }

            return ret;
        }

        private ProxyToken HandleOtherRequest(HttpRequestHeader header, DataAdapterToStream stm, ProxyNetworkService service)
        {
            Uri url;

            if (Uri.TryCreate(header.Path, UriKind.Absolute, out url))
            {
                // Use generic token so filters don't get used
                ProxyToken ret = new ProxyToken();

                ret.State.Add("url", url);
                ret.State.Add("stm", stm);
                ret.State.Add("header", header);

                ret.Client = new HttpProxyDummyClient(this, service);
                ret.Graph = _factory;

                return ret;
            }
            else
            {
                _logger.LogError(CANAPE.Net.Properties.Resources.HttpProxyServer_InvalidUrl, header.Path);

                // TODO: Put in some decent error codes
                ReturnResponse(null, 400, "Bad Request", header.Method, header.Version, stm);

                return null;
            }
        }

        private bool ProcessProxyAuth(HttpRequestHeader request)
        {
            bool ret = false;

            if (_config.RequireAuth)
            {
                if (request.Headers.HasHeader("Proxy-Authorization"))
                {
                    string[] values = request.Headers.GetHeaderValues("Proxy-Authorization").First().Split(new char[] { ' ' }, 2);

                    if (values.Length == 2)
                    {
                        if (values[0].Equals("Basic", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                string data = BinaryEncoding.Instance.GetString(Convert.FromBase64String(values[1]));

                                string[] vs = data.Split(new char[] { ':' }, 2);
                                if ((vs.Length == 0) || (String.IsNullOrWhiteSpace(vs[0])))
                                {
                                    _logger.LogError(Properties.Resources.FullHttpProxyServer_InvalidUsernamePasswordString);
                                }
                                else
                                {
                                    // Username case-insensitive, password case sensitive
                                    ret = vs[0].Equals(_config.ProxyUsername, StringComparison.OrdinalIgnoreCase)
                                        && _config.ProxyPassword.Equals(vs.Length > 1 ? vs[1] : String.Empty);
                                }
                            }
                            catch (FormatException)
                            {
                                _logger.LogError(Properties.Resources.FullHttpProxyServer_InvalidBase64Auth);
                            }
                        }
                        else
                        {
                            _logger.LogError(Properties.Resources.FullHttpProxyServer_OnlySupportBasicAuth);
                        }
                    }
                    else
                    {
                        _logger.LogError(Properties.Resources.FullHttpProxyServer_InvalidAuthLine);
                    }
                }
            }
            else
            {
                ret = true;
            }

            return ret;
        }

        private void FlushRequest(HttpRequestHeader request)
        {
            if (!request.IsConnect)
            {
                HttpParserConfig config = new HttpParserConfig();
                config.StreamBody = true;

                IEnumerator<HttpRequestDataChunk> e = request.ReadChunks(config).GetEnumerator();
                while (e.MoveNext())
                {
                }
            }
        }

        private bool MustCloseConnection(HttpRequestHeader request)
        {
            return request.Version.IsVersion10
                || request.Version.IsVersionUnknown
                || _config.Version10Proxy
                || request.Headers.HasHeader("Connection", "close")
                || request.Headers.HasHeader("Proxy-Connection", "close");
        }

        private bool HandleProxyAuthentication(DataReader reader, DataAdapterToStream stm, ref HttpRequestHeader request)
        {
            if (_config.RequireAuth)
            {
                bool auth = ProcessProxyAuth(request);

                if (!auth)
                {
                    ReturnResponse(request, 407, "Proxy Authentication Required", request.Method, request.Version,
                                   new HttpHeader[] { new HttpHeader("Proxy-Authenticate",
                            String.Format("Basic realm=\"{0}\"", _config.AuthRealm ?? "canape.local")) }, stm);

                    if (!MustCloseConnection(request))
                    {
                        // If version 1.1 server we can assume connection will probably stay up so re-read request
                        // Only give it one chance to get it right though
                        request = HttpParser.ReadRequestHeader(reader, false, _logger);

                        auth = ProcessProxyAuth(request);
                    }
                }

                return auth;
            }
            else
            {
                return true;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="adapter"></param>
        /// <param name="meta"></param>
        /// <param name="globalMeta"></param>
        /// <param name="service"></param>
        /// <returns></returns>
        public override ProxyToken Accept(IDataAdapter adapter, MetaDictionary meta, MetaDictionary globalMeta, ProxyNetworkService service)
        {
            ProxyToken token = null;

            if (_config.SslConfig.Enabled)
            {
                IDataAdapter client = null;
                INetworkLayer ssl = new TlsNetworkLayer(_config.SslConfig);

                ssl.Negotiate(ref adapter, ref client, null, _logger, null, null,
                      new PropertyBag("Root"), NetworkLayerBinding.Server);
            }

            if (adapter is HttpProxyDataAdapter)
            {
                HttpProxyDataAdapter proxyAdapter = (HttpProxyDataAdapter)adapter;

                token = new FullHttpProxyToken(proxyAdapter.Url.Host, proxyAdapter.Url.Port);

                token.State.Add("adapter", adapter);
            }
            else
            {
                DataAdapterToStream stm = new DataAdapterToStream(adapter);
                DataReader reader = new DataReader(stm);

                try
                {
                    HttpRequestHeader header = HttpParser.ReadRequestHeader(reader, false, _logger);

                    if (HandleProxyAuthentication(reader, stm, ref header))
                    {
                        // We just have a connect
                        if (header.IsConnect)
                        {
                            token = HandleConnect(header, stm);
                        }
                        else
                        {
                            token = HandleOtherRequest(header, stm, service);
                        }
                    }
                }
                catch (HttpStreamParserException ex)
                {
                    _logger.LogError(CANAPE.Net.Properties.Resources.HttpProxyServer_InvalidRequest, ex.Message);

                    // TODO: Put in some decent error codes
                    ReturnResponse(null, 400, "Bad Request", "GET", HttpVersion.Version11, stm);
                }
                catch (EndOfStreamException)
                {
                    token = null;
                }
            }

            return token;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <param name="meta"></param>
        /// <param name="globalMeta"></param>
        /// <param name="service"></param>
        /// <param name="client"></param>
        /// <returns></returns>
        public override IDataAdapter Complete(ProxyToken token, MetaDictionary meta, MetaDictionary globalMeta, ProxyNetworkService service, IDataAdapter client)
        {
            IDataAdapter ret = null;

            // An empty initial request indicates we are a full connection
            if (token.State.ContainsKey("header"))
            {
                HttpRequestHeader initialRequest = (HttpRequestHeader)token.State["header"];
                DataAdapterToStream stm = (DataAdapterToStream)token.State["stm"];

                if (token.Status == NetStatusCodes.Success)
                {
                    if (initialRequest.IsConnect)
                    {
                        ReturnResponse(null, 200, "Connection established", initialRequest.Method, initialRequest.Version, stm);

                        // Connect is transparent
                        ret = new StreamDataAdapter(stm);
                    }
                    else
                    {
                        // Use a proxy adapter
                        ret = new HttpProxyServerAdapter(this, stm, initialRequest, _logger);
                    }
                }
                else
                {
                    ReturnResponse(initialRequest, 404, "Not Found", initialRequest.Method, HttpVersion.Version11, stm);
                }
            }
            else
            {
                ret = (IDataAdapter)token.State["adapter"];
            }

            token.State.Clear();

            return ret;
        }

        /// <summary>
        /// ToString implementation
        /// </summary>
        /// <returns>Return to string information</returns>
        public override string ToString()
        {
            return Properties.Resources.HttpProxyServer_ToString;
        }
    }
}
