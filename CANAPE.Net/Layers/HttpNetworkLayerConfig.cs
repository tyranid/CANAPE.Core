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
using CANAPE.Net.Protocols.Parser;
using System;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// Configuration class for HTTP network layer, TODO: Implement filter set to configure this for specific requests
    /// </summary>
    public class HttpNetworkLayerConfig
    {
        /// <summary>
        /// Array of configuration entries
        /// </summary>
        public HttpLayerConfigEntry[] ConfigEntries { get; set; }

        /// <summary>
        /// The default configuration if no specific match
        /// </summary>
        public HttpLayerConfigEntry DefaultEntry { get; set; }

        /// <summary>
        /// Sets a maximum length for a buffered stream, anything above will be converted to chunked. &lt;= 0 indicates no limit
        /// </summary>
        public long BufferedRequestMaxLength { get; set; }

        /// <summary>
        /// Sets a maximum length for a buffered stream, anything above will be converted to chunked. &lt;= 0 indicates no limit
        /// </summary>
        public long BufferedResponseMaxLength { get; set; }

        /// <summary>
        /// Specify how big a chunk to read in per chunk when in streaming mode, set to 0 to disable which
        /// will send data with no buffering, this is advisory, it won't work in chunked encoding, 
        /// and you might have short reads sometimes
        /// </summary>
        public int RequestStreamChunkSize { get; set; }

        /// <summary>
        /// If true then applies stricter parsing on the data, will cause more requests to fail
        /// </summary>
        public bool RequestStrictParsing { get; set; }

        /// <summary>
        /// Specify how big a chunk to read in per chunk when in streaming mode, set to 0 to disable which
        /// will send data with no buffering, this is advisory, it won't work in chunked encoding, 
        /// and you might have short reads sometimes
        /// </summary>
        public int ResponseStreamChunkSize { get; set; }

        /// <summary>
        /// If true then applies stricter parsing on the data, will cause more requests to fail
        /// </summary>
        public bool ResponseStrictParsing { get; set; }

        /// <summary>
        /// Automatically handle 100 continues (remove from request, remove from response)
        /// </summary>
        public bool Handle100Continue { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        public HttpNetworkLayerConfig()
        {
            ConfigEntries = new HttpLayerConfigEntry[0];
            DefaultEntry = new HttpLayerConfigEntry();
        }

        private HttpLayerConfigEntry GetEntry(Func<HttpLayerConfigEntry, bool> matcher)
        {
            foreach (HttpLayerConfigEntry entry in ConfigEntries)
            {
                if (matcher(entry))
                {
                    return entry;
                }
            }

            return DefaultEntry;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public HttpLayerConfigEntry GetEntry(HttpRequestHeader request)
        {
            return GetEntry(e => e.IsMatch(request));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <returns></returns>
        public HttpLayerConfigEntry GetEntry(HttpRequestHeader request, HttpResponseHeader response)
        {
            return GetEntry(e => e.IsMatch(request, response));
        }
    }
}
