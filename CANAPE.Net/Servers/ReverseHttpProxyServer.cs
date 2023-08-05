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
using CANAPE.Net.Layers;
using CANAPE.Net.Protocols.Parser;
using CANAPE.Net.Tokens;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.IO;

namespace CANAPE.Net.Servers
{
    /// <summary>
    /// 
    /// </summary>
    public class ReverseHttpProxyServer : ProxyServer
    {
        private HttpProxyServerConfig _config;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="config"></param>
        /// <param name="logger"></param>
        public ReverseHttpProxyServer(HttpProxyServerConfig config, Logger logger)
            : base(logger)
        {
            _config = config;
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

        private void ReturnResponse(HttpRequestHeader request, int responseCode, string message, string method, HttpVersion version, DataAdapterToStream stm)
        {
            ReturnResponse(request, responseCode, message, method, version, new HttpHeader[0], stm);
        }

        private void ReturnResponse(HttpRequestHeader request, int responseCode, string message,
                                    string method, HttpVersion version, IEnumerable<HttpHeader> sendHeaders,
                                    DataAdapterToStream stm)
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

        private Uri GetUri(string host, TcpClientDataAdapter tcpAdapter)
        {
            Uri ret = null;
            int port = _config.SslConfig.Enabled ? 443 : 80;

            // TODO: Should handle this case, perhaps just make it optional

            //if ((tcpAdapter != null) && (tcpAdapter.Socket.Client.LocalEndPoint is System.Net.IPEndPoint))
            //{
            //    port = ((System.Net.IPEndPoint)tcpAdapter.Socket.Client.LocalEndPoint).Port;
            //}

            if (!String.IsNullOrWhiteSpace(host))
            {
                try
                {
                    if (!host.Contains(":"))
                    {
                        host = String.Format("{0}:{1}", host, port);
                    }

                    if (_config.SslConfig.Enabled)
                    {
                        ret = new Uri("https://" + host);
                    }
                    else
                    {
                        ret = new Uri("http://" + host);
                    }
                }
                catch (UriFormatException)
                {
                }
            }

            return ret;
        }

        private ProxyToken HandleOtherRequest(HttpRequestHeader header, DataAdapterToStream stm, TcpClientDataAdapter tcpAdapter)
        {
            string host = null;

            foreach (HttpHeader pair in header.Headers)
            {
                if (pair.Name.Equals("host", StringComparison.OrdinalIgnoreCase))
                {
                    host = pair.Value;
                }
            }

            Uri url = GetUri(host, tcpAdapter);

            if (url != null)
            {
                // Use generic token so filters don't get used
                IpProxyToken ret = new IpProxyToken(null, url.Host, url.Port, IpProxyToken.IpClientType.Tcp, false);

                if (_config.SslConfig.Enabled)
                {
                    ret.Layers = new INetworkLayer[1];
                    ret.Layers[0] = new TlsNetworkLayer(new TlsNetworkLayerConfig(false, true) { Enabled = true });
                }

                ret.State.Add("url", url);
                ret.State.Add("stm", stm);
                ret.State.Add("header", header);

                return ret;
            }
            else
            {
                _logger.LogError(CANAPE.Net.Properties.Resources.HttpProxyServer_InvalidUrl, header.Path);

                ReturnResponse(null, 400, "Bad Request", header.Method, header.Version, stm);

                return null;
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

            TcpClientDataAdapter tcpAdapter = adapter as TcpClientDataAdapter;

            if (_config.SslConfig.Enabled)
            {
                IDataAdapter client = null;
                INetworkLayer ssl = new TlsNetworkLayer(_config.SslConfig);

                ssl.Negotiate(ref adapter, ref client, null, _logger, null, null,
                      new PropertyBag("Root"), NetworkLayerBinding.Server);
            }

            DataAdapterToStream stm = new DataAdapterToStream(adapter);
            DataReader reader = new DataReader(stm);

            try
            {
                HttpRequestHeader header = HttpParser.ReadRequestHeader(reader, false, _logger);

                token = HandleOtherRequest(header, stm, tcpAdapter);
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

            return token;
        }

        private class HttpProxyServerAdapter : BaseDataAdapter
        {
            private DataAdapterToStream _stm;
            private DataWriter _writer;
            private HttpRequestHeader _request;
            private IEnumerator<HttpRequestDataChunk> _chunks;
            private HttpParserConfig _config;
            private Logger _logger;

            public HttpProxyServerAdapter(DataAdapterToStream stm, HttpRequestHeader initialRequest, Logger logger)
            {
                _stm = stm;
                _writer = new DataWriter(_stm);
                _request = initialRequest;
                _config = new HttpParserConfig();
                _config.StreamBody = true;
                _logger = logger;

                Description = stm.Description;
            }

            public override DataFrame Read()
            {
                try
                {
                    if (_request == null)
                    {
                        _request = HttpParser.ReadRequestHeader(new DataReader(_stm), false, _logger);
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

                    MemoryStream stm = new MemoryStream();
                    DataWriter writer = new DataWriter(stm);

                    chunk.WriteChunk(writer);

                    return stm.ToArray().ToDataFrame();
                }
                catch (EndOfStreamException)
                {
                    return null;
                }
            }

            public override void Write(DataFrame data)
            {
                _writer.WriteBytes(data.ToArray());
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
                        ret = new HttpProxyServerAdapter(stm, initialRequest, _logger);
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
            return Properties.Resources.ReverseHttpProxyServer_ToString;
        }
    }
}
