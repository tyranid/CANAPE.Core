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
using CANAPE.Net.Protocols.Parser;
using CANAPE.Net.Tokens;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// Class for HTTP network layer
    /// </summary>
    public class HttpNetworkLayer : INetworkLayer
    {
        private HttpNetworkLayerConfig _config;
        private string _upgradeType;
        private bool _upgrading;

        /// <summary>
        /// Constructor, default configuration
        /// </summary>
        public HttpNetworkLayer()
            : this(new HttpNetworkLayerConfig())
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="config">Layer configuration</param>
        public HttpNetworkLayer(HttpNetworkLayerConfig config)
        {
            _config = config;
            _upgradeType = null;
        }

        internal abstract class BaseHttpDataAdapter : BaseDataAdapter
        {
            private int _isDisposed;
            protected Logger _logger;
            protected HttpNetworkLayer _layer;
            protected IDataAdapter _adapter;

            protected BaseHttpDataAdapter(IDataAdapter adapter, Logger logger, HttpNetworkLayer layer)
            {
                _adapter = adapter;
                Description = _adapter.Description;
                _logger = logger;
                _layer = layer;
            }

            protected override void OnDispose(bool disposing)
            {
                int isDisposed = Interlocked.Exchange(ref _isDisposed, 1);
                if (isDisposed == 0)
                {
                    _adapter.Dispose();
                }
            }

            public override bool CanTimeout
            {
                get
                {
                    return _adapter.CanTimeout;
                }
            }

            public override int ReadTimeout
            {
                get
                {
                    return _adapter.ReadTimeout;
                }
                set
                {
                    _adapter.ReadTimeout = value;
                }
            }

            public static IEnumerable<DataFrame> ReadFrames(DataFrame firstFrame, DataReader reader)
            {
                if (firstFrame != null)
                {
                    yield return firstFrame;
                }

                byte[] data = reader.ReadBytes(HttpParserConfig.DEFAULT_CHUNK_SIZE, false);

                while (data.Length > 0)
                {
                    yield return data.ToDataFrame();

                    data = reader.ReadBytes(HttpParserConfig.DEFAULT_CHUNK_SIZE, false);
                }
            }
        }

        internal sealed class HttpRequestDataAdapter : BaseHttpDataAdapter
        {
            HttpRequestHeader _currentHeader;
            IEnumerator<DataFrame> _chunks;
            DataReader _reader;
            MemoryStream _responseStream = new MemoryStream();
            bool _isTransparent;

            public HttpRequestDataAdapter(IDataAdapter adapter, Logger logger, HttpNetworkLayer layer)
                : base(adapter, logger, layer)
            {
                _reader = new DataReader(adapter);
            }

            private HttpParserConfig CreateConfig(HttpRequestHeader header)
            {
                HttpParserConfig config = new HttpParserConfig();

                HttpLayerConfigEntry entry = _layer._config.GetEntry(header);

                config.StreamBody = entry.RequestStreamBody;
                config.StreamChunkSize = _layer._config.RequestStreamChunkSize;
                config.StrictParsing = _layer._config.RequestStrictParsing;

                if (_layer._config.BufferedRequestMaxLength != 0 && (header.ContentLength > _layer._config.BufferedRequestMaxLength))
                {
                    config.StreamBody = true;
                }

                return config;
            }

            public override DataFrame Read()
            {
                DataFrame frame = null;

                try
                {
                    if (_chunks == null || !_chunks.MoveNext())
                    {
                        char firstChar = _reader.ReadChar();

                        // Check whether we need to upgrade the connection to raw data, could even at this point actually implement 
                        // TLS upgrade (and put back the HTTP parser on top?)                                                                      
                        if (_isTransparent)
                        {
                            // If transparent send the first chunk along and don't increment enumerator
                            _chunks = BaseHttpDataAdapter.ReadFrames(new byte[] { (byte)firstChar }.ToDataFrame(), _reader).GetEnumerator();
                        }
                        else
                        {
                            _currentHeader = HttpParser.ReadRequestHeader(_reader, _layer._config.RequestStrictParsing, _logger, new char[] { firstChar });

                            if (_currentHeader.Version.IsVersion11 && _layer._config.Handle100Continue)
                            {
                                bool sendResponse = false;

                                int i = 0;

                                while (i < _currentHeader.Headers.Count)
                                {
                                    var header = _currentHeader.Headers[i];

                                    // Remove expect headers
                                    if (header.Name.Equals("Expect", StringComparison.OrdinalIgnoreCase) && header.Value.Equals("100-continue", StringComparison.OrdinalIgnoreCase))
                                    {
                                        _currentHeader.Headers.RemoveAt(i);
                                        sendResponse = true;
                                    }
                                    else
                                    {
                                        i++;
                                    }
                                }

                                if (sendResponse)
                                {
                                    _adapter.Write("HTTP/1.1 100 Continue\r\n\r\n".ToDataFrame());
                                }
                            }

                            _chunks = _currentHeader.ReadFrames(CreateConfig(_currentHeader)).GetEnumerator();
                        }

                        // Increment to next chunk
                        if (!_chunks.MoveNext())
                        {
                            throw new EndOfStreamException();
                        }
                    }

                    frame = _chunks.Current;
                }
                catch (EndOfStreamException)
                {
                    frame = null;
                }

                return frame;
            }

            // For response don't really care about what we send
            public override void Write(DataFrame data)
            {
                if (!_isTransparent && _layer._upgrading)
                {
                    // Wait for upgrade header

                    byte[] buf = data.ToArray();

                    lock (_responseStream)
                    {
                        _responseStream.Position = _responseStream.Length;
                        _responseStream.Write(buf, 0, buf.Length);
                        _responseStream.Position = 0;

                        try
                        {
                            HttpResponseHeader header = HttpParser.ReadResponseHeader(new DataReader(_responseStream), false, _logger);

                            if (header.IsUpgradeResponse)
                            {
                                foreach (HttpHeader pair in header.Headers)
                                {
                                    if (pair.Name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase))
                                    {
                                        _layer._upgradeType = pair.Value;
                                        break;
                                    }
                                }

                                _isTransparent = true;
                                _layer._upgrading = false;
                            }
                            else
                            {
                                _layer._upgrading = false;
                            }
                        }
                        catch (HttpStreamParserException)
                        {
                        }
                    }
                }

                _adapter.Write(data);
            }
        }

        internal sealed class HttpResponseDataAdapter : BaseHttpDataAdapter
        {
            HttpResponseHeader _currentHeader;
            IEnumerator<DataFrame> _chunks;
            Queue<HttpRequestHeader> _requests;
            MemoryStream _requestStream = new MemoryStream();
            DataReader _reader;
            bool _isTransparent;

            public HttpResponseDataAdapter(IDataAdapter adapter, Logger logger, HttpNetworkLayer layer)
                : base(adapter, logger, layer)
            {
                _requests = new Queue<HttpRequestHeader>();
                _reader = new DataReader(adapter);
            }

            private HttpParserConfig CreateConfig(HttpResponseHeader response, HttpRequestHeader request)
            {
                HttpParserConfig config = new HttpParserConfig();

                HttpLayerConfigEntry entry = _layer._config.GetEntry(request, response);

                config.ConvertToChunked = entry.ConvertToChunked;
                config.StreamBody = entry.ResponseStreamBody;
                config.StreamChunkSize = _layer._config.ResponseStreamChunkSize;
                config.StrictParsing = _layer._config.ResponseStrictParsing;

                if (_layer._config.BufferedResponseMaxLength != 0 && (response.ContentLength > _layer._config.BufferedResponseMaxLength))
                {
                    config.StreamBody = true;
                }

                return config;
            }


            public override DataFrame Read()
            {
                DataFrame frame = null;

                try
                {
                    if (_chunks == null || !_chunks.MoveNext())
                    {
                        if (_isTransparent)
                        {
                            _chunks = BaseHttpDataAdapter.ReadFrames(null, _reader).GetEnumerator();
                        }
                        else
                        {
                            _currentHeader = HttpParser.ReadResponseHeader(_reader, _layer._config.ResponseStrictParsing, _logger);

                            HttpRequestHeader request = null;

                            lock (_requests)
                            {
                                if (_requests.Count > 0)
                                {
                                    // If we have a queued request then dequeue and set head response
                                    request = _requests.Dequeue();
                                }
                            }

                            lock (_requestStream)
                            {
                                if (request == null)
                                {
                                    try
                                    {
                                        _requestStream.Position = 0;
                                        request = HttpParser.ReadRequestHeader(new DataReader(_requestStream), false, _logger);
                                    }
                                    catch (EndOfStreamException)
                                    {
                                        // Ignore end of stream, might just mean we sent garbage to the server which we can't parse
                                    }
                                }

                                _requestStream.SetLength(0);
                            }

                            if (request != null)
                            {
                                _currentHeader.SetHeadRequest(request.IsHead);
                                _currentHeader.SetConnectRequest(request.IsConnect);

                                if (_currentHeader.Is100Continue)
                                {
                                    // If a 100 status response then requeue the request
                                    lock (_requests)
                                    {
                                        HttpRequestHeader[] headers = _requests.ToArray();
                                        _requests.Clear();
                                        // Unlikely that another request will come as client is probably waiting for 100 status, but might as well be sure
                                        _requests.Enqueue(request);
                                        foreach (HttpRequestHeader head in headers)
                                        {
                                            _requests.Enqueue(head);
                                        }
                                    }
                                }
                            }

                            if (_currentHeader.IsUpgradeResponse)
                            {
                                _layer._upgrading = true;
                                _isTransparent = true;
                            }

                            _chunks = _currentHeader.ReadFrames(CreateConfig(_currentHeader, request)).GetEnumerator();
                        }

                        if (!_chunks.MoveNext())
                        {
                            throw new EndOfStreamException();
                        }
                    }

                    frame = _chunks.Current;
                }
                catch (EndOfStreamException)
                {
                    frame = null;
                }

                return frame;
            }

            public override void Write(DataFrame frame)
            {
                if (!_isTransparent)
                {
                    var chunk = frame.GetValueNoThrow<HttpRequestDataChunk>();

                    if (chunk != null)
                    {
                        // Enqueue the first chunk as a request
                        if (chunk.ChunkNumber == 0)
                        {
                            lock (_requests)
                            {
                                _requests.Enqueue(chunk.ToHeader());
                            }
                        }

                        _adapter.Write(frame);
                    }
                    else
                    {
                        // If we can't use pre-parsed then queue the data up
                        byte[] data = frame.ToArray();

                        lock (_requestStream)
                        {
                            _requestStream.Position = _requestStream.Length;

                            _requestStream.Write(data, 0, data.Length);
                        }

                        _adapter.Write(frame);
                    }
                }
                else
                {
                    // In transparent mode just pass along
                    _adapter.Write(frame);
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="server"></param>
        /// <param name="client"></param>
        /// <param name="token"></param>
        /// <param name="logger"></param>
        /// <param name="meta"></param>
        /// <param name="globalMeta"></param>
        /// <param name="properties"></param>
        /// <param name="defaultBinding"></param>
        public void Negotiate(ref IDataAdapter server, ref IDataAdapter client, ProxyToken token, Logger logger,
            MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties, NetworkLayerBinding defaultBinding)
        {
            if (defaultBinding == NetworkLayerBinding.Default)
            {
                defaultBinding = NetworkLayerBinding.ClientAndServer;
            }

            if (Binding != NetworkLayerBinding.Default)
            {
                defaultBinding = Binding;
            }

            if ((defaultBinding & NetworkLayerBinding.Server) == NetworkLayerBinding.Server)
            {
                server = new HttpRequestDataAdapter(server, logger, this);
            }

            if ((defaultBinding & NetworkLayerBinding.Client) == NetworkLayerBinding.Client)
            {
                client = new HttpResponseDataAdapter(client, logger, this);
            }
        }

        /// <summary>
        /// Current binding mode
        /// </summary>
        public NetworkLayerBinding Binding
        {
            get; set;
        }
    }
}
