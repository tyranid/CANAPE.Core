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
using CANAPE.DataFrames;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace CANAPE.Net.Protocols.Parser
{
    /// <summary>
    /// Class representing the HTTP response header
    /// </summary>
    public class HttpResponseHeader
    {
        /// <summary>
        /// 
        /// </summary>
        public int ResponseCode { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public string Message { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public HttpVersion Version { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public List<HttpHeader> Headers { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public long ContentLength { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public bool ChunkedEncoding { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public bool ReadToEnd { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public bool HasBody { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public bool HeadRequest { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public bool ConnectRequest { get; private set; }

        /// <summary>
        /// Set the response as originating from a head request
        /// </summary>
        /// <param name="head"></param>
        public void SetHeadRequest(bool head)
        {
            HeadRequest = head;
            HasBody = !head;
        }

        /// <summary>
        /// Set the response as originating from a connect request
        /// </summary>
        /// <param name="connect"></param>
        public void SetConnectRequest(bool connect)
        {
            ConnectRequest = connect;
        }

        private DataReader _reader;
        private string _initialData;

        internal HttpResponseHeader(DataReader reader, string initialData)
            : this(reader, new HttpHeader[0], 200, String.Empty, HttpVersion.VersionUnknown)
        {
            _initialData = initialData;
        }

        internal HttpResponseHeader(DataReader reader, IEnumerable<HttpHeader> headers,
                                    int responseCode, string message, HttpVersion version)
        {
            _reader = reader;
            Headers = new List<HttpHeader>(headers);
            ResponseCode = responseCode;
            Message = message;
            Version = version;

            if (ResponseCode != 304)
            {
                ContentLength = HttpParser.GetContentLength(Headers);
                ChunkedEncoding = HttpParser.IsChunkedEncoding(Headers);
                HasBody = true;
            }

            // Always trust a content-length if it exists
            if (Headers.Count(p => p.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) == 0)
            {
                // Otherwise if version unknown, 1.0 or connection will close set then indicate we will read to the end
                if (Version.IsVersionUnknown || Version.IsVersion10 || (Headers.Count(p => p.Name.Equals("Connection", StringComparison.OrdinalIgnoreCase) && p.Value.Equals("close", StringComparison.OrdinalIgnoreCase)) > 0))
                {
                    ReadToEnd = true;
                }
            }
        }

        private static byte[] ReadChunkedEncoding(DataReader stm, out string extension)
        {
            extension = null;

            string s = stm.ReadLine();
            if (s.Length == 0)
            {
                return new byte[0];
            }

            string lenstr = s.Trim();
            if (lenstr.Length == 0)
            {
                return new byte[0];
            }

            string[] values = lenstr.Split(new char[] { ';' }, 2);

            lenstr = values[0];

            if (values.Length > 1)
            {
                extension = values[1];
            }

            int lenval = int.Parse(lenstr, NumberStyles.HexNumber);

            if (lenval > 0)
            {
                byte[] data = stm.ReadBytes(lenval);
                stm.ReadLine();

                return data;
            }
            else
            {
                // Read out final trailing data
                string line = stm.ReadLine();
                while ((line.Length > 0) && (line.Trim().Length > 0))
                {
                    line = stm.ReadLine();
                }
            }

            return new byte[0];
        }

        /// <summary>
        /// Indicates this is a 100 continue
        /// </summary>
        public bool Is100Continue
        {
            get { return ResponseCode == 100; }
        }

        /// <summary>
        /// Indicates this is an upgrade response
        /// </summary>
        public bool IsUpgradeResponse
        {
            get { return ResponseCode == 101; }
        }

        private HttpResponseDataChunk CreateChunk(byte[] body, int chunkNumber, bool finalChunk, bool convertToChunked)
        {
            HttpResponseDataChunk ret = new HttpResponseDataChunk(this);

            ret.ChunkNumber = chunkNumber;
            ret.FinalChunk = finalChunk;
            ret.Body = body;

            if (convertToChunked)
            {
                ret.ChunkedEncoding = true;
                List<HttpHeader> headers = new List<HttpHeader>();

                // Remove any content-length and existing Transfer-Encoding chunked
                foreach (HttpHeader pair in ret.Headers)
                {
                    if (!(pair.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
                        || (pair.Name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
                        && pair.Value.Equals("chunked", StringComparison.OrdinalIgnoreCase))))
                    {
                        headers.Add(pair);
                    }
                }

                headers.Add(new HttpHeader("Transfer-Encoding", "chunked"));
                ret.Headers = headers.ToArray();
            }


            return ret;
        }

        private IEnumerable<HttpResponseDataChunk> ReadChunksStreamedLength(HttpParserConfig config)
        {
            long length = ContentLength;
            int chunkSize = config.StreamChunkSize;
            bool waitForAll = true;
            int chunkNumber = 0;

            // Can only convert if returning HTTP/1.1
            bool convertToChunked = config.ConvertToChunked && Version.IsVersion11;

            if (chunkSize <= 0)
            {
                waitForAll = false;
                chunkSize = HttpParserConfig.DEFAULT_CHUNK_SIZE;
            }

            if (ReadToEnd)
            {
                if (_initialData != null)
                {
                    List<byte> block = new List<byte>(BinaryEncoding.Instance.GetBytes(_initialData));

                    if (!_reader.Eof)
                    {
                        // Worst case you will get chunkSize + 4
                        block.AddRange(waitForAll ? _reader.ReadToEnd(chunkSize) : _reader.ReadBytes(chunkSize, false));
                    }

                    yield return CreateChunk(block.ToArray(), chunkNumber++, _reader.Eof, convertToChunked);
                }

                while (!_reader.Eof)
                {
                    byte[] block = waitForAll ? _reader.ReadToEnd(chunkSize) : _reader.ReadBytes(chunkSize, false);

                    yield return CreateChunk(block, chunkNumber++, _reader.Eof, convertToChunked);
                }
            }
            else
            {
                while (length > 0)
                {
                    int readLength = length > chunkSize ? chunkSize : (int)length;

                    byte[] data = _reader.ReadBytes(readLength, waitForAll);

                    // While we are reading we wouldn't expect no data to be returned
                    if (data.Length == 0)
                    {
                        throw new EndOfStreamException();
                    }

                    length -= data.Length;

                    yield return CreateChunk(data, chunkNumber++, length == 0, config.ConvertToChunked);
                }
            }
        }

        private IEnumerable<HttpResponseDataChunk> ReadChunksConnect(HttpParserConfig config)
        {
            int chunkNumber = 0;

            while (true)
            {
                byte[] data = _reader.ReadBytes(HttpParserConfig.DEFAULT_CHUNK_SIZE, false);

                if (data.Length == 0)
                {
                    throw new EndOfStreamException();
                }

                HttpResponseDataChunk chunk = new HttpResponseDataChunk(this);

                chunk.ChunkNumber = chunkNumber;

                if (chunkNumber < int.MaxValue)
                {
                    chunkNumber++;
                }

                // Cast to length, really should just ignore any data set greater than a set amount
                chunk.Body = data;

                yield return chunk;
            }

        }

        private IEnumerable<HttpResponseDataChunk> ReadChunksStreamedChunked(HttpParserConfig config)
        {
            string extension;
            int chunkNumber = 0;

            List<HttpHeader> headers = new List<HttpHeader>(Headers);

            if (config.DowngradeChunkedToHttp10)
            {
                int i = 0;
                while (i < headers.Count)
                {
                    if (headers[i].Name.Equals("transfer-encoding", StringComparison.OrdinalIgnoreCase)
                        && headers[i].Value.Equals("chunked", StringComparison.OrdinalIgnoreCase))
                    {
                        headers.RemoveAt(i);
                    }
                    else
                    {
                        i++;
                    }
                }
            }

            byte[] ret = ReadChunkedEncoding(_reader, out extension);

            do
            {
                HttpResponseDataChunk chunk = new HttpResponseDataChunk(this);
                chunk.ChunkNumber = chunkNumber++;
                chunk.Body = ret;

                if (config.DowngradeChunkedToHttp10)
                {
                    chunk.Headers = headers.ToArray();
                    chunk.Version = HttpVersion.Version10;
                }
                else
                {
                    chunk.ChunkedEncoding = true;
                }

                chunk.ChunkExtension = extension;
                ret = ReadChunkedEncoding(_reader, out extension);
                chunk.FinalChunk = ret.Length == 0;

                yield return chunk;
            }
            while (ret.Length > 0);
        }

        private IEnumerable<HttpResponseDataChunk> ReadChunksBuffered(HttpParserConfig config)
        {
            HttpResponseDataChunk chunk = new HttpResponseDataChunk(this);
            chunk.ChunkNumber = 0;
            chunk.FinalChunk = true;

            if (!ChunkedEncoding)
            {
                if (ReadToEnd)
                {
                    if (_initialData != null)
                    {
                        List<byte> data = new List<byte>(BinaryEncoding.Instance.GetBytes(_initialData));
                        if (!_reader.Eof)
                        {
                            data.AddRange(_reader.ReadToEnd());
                        }

                        chunk.Body = data.ToArray();
                    }
                    else
                    {
                        chunk.Body = _reader.ReadToEnd();
                    }
                }
                else
                {
                    long length = ContentLength;

                    if (length > 0)
                    {
                        chunk.Body = _reader.ReadBytes((int)length);
                    }
                    else
                    {
                        chunk.Body = new byte[0];
                    }
                }
            }
            else
            {
                List<byte> body = new List<byte>();
                string extension = null;
                byte[] ret = ReadChunkedEncoding(_reader, out extension);

                while (ret.Length > 0)
                {
                    body.AddRange(ret);

                    ret = ReadChunkedEncoding(_reader, out extension);
                }

                chunk.ChunkedEncoding = true;
                chunk.Body = body.ToArray();
            }

            return new HttpResponseDataChunk[] { chunk };
        }

        /// <summary>
        /// TODO: Implement chunking
        /// </summary>        
        /// <returns>An enumerable list of chunks</returns>
        public IEnumerable<HttpResponseDataChunk> ReadChunks(HttpParserConfig config)
        {
            if (ConnectRequest)
            {
                return ReadChunksConnect(config);
            }
            else if (HasBody && !Is100Continue && ResponseCode != 304)
            {
                if (config.StreamBody)
                {
                    if (!ChunkedEncoding)
                    {
                        return ReadChunksStreamedLength(config);
                    }
                    else
                    {
                        return ReadChunksStreamedChunked(config);
                    }
                }
                else
                {
                    return ReadChunksBuffered(config);
                }
            }
            else
            {
                // No body, then just return the chunk as headers
                HttpResponseDataChunk chunk = new HttpResponseDataChunk(this);
                chunk.ChunkNumber = 0;
                chunk.FinalChunk = true;

                return new HttpResponseDataChunk[] { chunk };
            }
        }

        /// <summary>
        /// Read frames from stream
        /// </summary>
        /// <param name="config">An enumerable list of frames</param>
        /// <returns>The frames</returns>
        public IEnumerable<DataFrame> ReadFrames(HttpParserConfig config)
        {
            return ReadChunks(config).Select(c => c.ToDataFrame());
        }
    }
}
