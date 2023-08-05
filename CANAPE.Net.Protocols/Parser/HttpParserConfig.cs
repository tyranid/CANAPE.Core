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

namespace CANAPE.Net.Protocols.Parser
{
    /// <summary>
    /// Configuration for HTTP reading
    /// </summary>
    public class HttpParserConfig
    {
        /// <summary>
        /// Default chunk size
        /// </summary>
        public const int DEFAULT_CHUNK_SIZE = 8 * 1024;

        /// <summary>
        /// If true body will be streamed rather than buffered up
        /// </summary>
        public bool StreamBody { get; set; }

        /// <summary>
        /// Specify how big a chunk to read in per chunk when in streaming mode, set to 0 to disable which
        /// will send data with no buffering, this is advisory, it won't work in chunked encoding, 
        /// and you might have short reads sometimes
        /// </summary>
        public int StreamChunkSize { get; set; }

        /// <summary>
        /// If true then applies stricter parsing on the data, will cause more requests to fail
        /// </summary>
        public bool StrictParsing { get; set; }

        /// <summary>
        /// Convert HTTP/1.1 content-length format response to chunked encoding (for easier manipulation)
        /// Only applicable if StreamBody has been set, otherwise the entire body is buffered anyway
        /// </summary>
        public bool ConvertToChunked { get; set; }

        /// <summary>
        /// Convert HTTP/1.1 chunked encoding response to streamed 1.0 (or lower) with no content-length
        /// </summary>
        public bool DowngradeChunkedToHttp10 { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        public HttpParserConfig()
        {
            StreamChunkSize = DEFAULT_CHUNK_SIZE;
        }
    }
}
