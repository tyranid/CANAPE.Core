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
using System.IO;
using System.Linq;

namespace CANAPE.Net.Protocols.Parser
{
    /// <summary>
    /// The header for a HTTP request
    /// </summary>
    public sealed class HttpRequestHeader
    {
        /// <summary>
        /// 
        /// </summary>
        public string Method { get; private set; }
        /// <summary>
        /// 
        /// </summary>
        public string Path { get; private set; }
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

        private DataReader _reader;

        /// <summary>
        /// 
        /// </summary>
        public bool IsGet
        {
            get { return Method.Equals("GET", StringComparison.OrdinalIgnoreCase); }
        }

        /// <summary>
        /// 
        /// </summary>
        public bool IsHead
        {
            get { return Method.Equals("HEAD", StringComparison.OrdinalIgnoreCase); }
        }

        /// <summary>
        /// 
        /// </summary>
        public bool IsConnect
        {
            get { return Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase); }
        }

        // Create a default header
        internal HttpRequestHeader() : this(null, new HttpHeader[0], "GET", "/", HttpVersion.Version10)
        {
        }

        internal HttpRequestHeader(DataReader reader, IEnumerable<HttpHeader> headers, string method, string path, HttpVersion version)
        {
            _reader = reader;
            Headers = new List<HttpHeader>(headers);
            Method = method;
            Path = path;
            Version = version;

            // These methods can't have a content length
            if (IsGet || IsHead)
            {
                ContentLength = 0;
            }
            else
            {
                ContentLength = HttpParser.GetContentLength(Headers);
            }
        }

        private IEnumerable<HttpRequestDataChunk> ReadChunksStreamed(HttpParserConfig config)
        {
            long length = ContentLength;
            int chunkSize = config.StreamChunkSize;
            bool waitForAll = true;
            int chunkNumber = 0;

            if (chunkSize <= 0)
            {
                waitForAll = false;
                chunkSize = HttpParserConfig.DEFAULT_CHUNK_SIZE;
            }

            // If we are expecting 100 continue then we have to 
            // send the header first otherwise this will block if we have a length
            // Also send if length is as there will be no following data
            if ((length == 0) || Headers.HasHeader("Expect", "100-continue"))
            {
                HttpRequestDataChunk chunk = new HttpRequestDataChunk(this);

                chunk.ChunkNumber = chunkNumber++;

                yield return chunk;
            }

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

                HttpRequestDataChunk chunk = new HttpRequestDataChunk(this);

                chunk.ChunkNumber = chunkNumber++;
                chunk.FinalChunk = length == 0;

                // Cast to length, really should just ignore any data set greater than a set amount
                chunk.Body = data;

                yield return chunk;
            }
        }

        private IEnumerable<HttpRequestDataChunk> ReadChunksConnect(HttpParserConfig config)
        {
            int chunkNumber = 0;

            while (true)
            {
                byte[] data = _reader.ReadBytes(HttpParserConfig.DEFAULT_CHUNK_SIZE, false);

                if (data.Length == 0)
                {
                    throw new EndOfStreamException();
                }

                HttpRequestDataChunk chunk = new HttpRequestDataChunk(this);

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

        private IEnumerable<HttpRequestDataChunk> ReadChunksBuffered(HttpParserConfig config)
        {
            long length = ContentLength;
            int chunkNumber = 0;

            HttpRequestDataChunk chunk = new HttpRequestDataChunk(this);

            // If we are expecting 100 continue then we have to 
            // send the header first otherwise this will block if we have a length
            if (Headers.HasHeader("Expect", "100-continue") && (length > 0))
            {
                chunk.ChunkNumber = chunkNumber++;

                yield return chunk;

                chunk = new HttpRequestDataChunk(this);
            }

            chunk.ChunkNumber = chunkNumber;
            chunk.FinalChunk = true;

            if (length > 0)
            {
                // Cast to length, really should just ignore any data set greater than a set amount
                chunk.Body = _reader.ReadBytes((int)length);
            }

            yield return chunk;
        }

        /// <summary>
        /// Read chunks from stream
        /// </summary>        
        /// <returns>An enumerable list of chunks</returns>
        public IEnumerable<HttpRequestDataChunk> ReadChunks(HttpParserConfig config)
        {
            if (IsConnect)
            {
                return ReadChunksConnect(config);
            }
            else if (config.StreamBody && ContentLength > 0)
            {
                return ReadChunksStreamed(config);
            }
            else
            {
                return ReadChunksBuffered(config);
            }
        }

        /// <summary>
        /// Read frames from sttream
        /// </summary>
        /// <param name="config">An enumerable list of frames</param>
        /// <returns>The frames</returns>
        public IEnumerable<DataFrame> ReadFrames(HttpParserConfig config)
        {
            return ReadChunks(config).Select(c => c.ToDataFrame());
        }

        /// <summary>
        /// Read the entire request body
        /// </summary>
        /// <returns>The request data chunk for the request</returns>
        public HttpRequestDataChunk ReadRequest()
        {
            return ReadChunks(new HttpParserConfig()).First();
        }
    }
}
