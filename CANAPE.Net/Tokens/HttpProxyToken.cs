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
using CANAPE.Utils;
using System;

namespace CANAPE.Net.Tokens
{
    /// <summary>
    /// Token for a HTTP proxy
    /// </summary>
    internal class HttpProxyToken : IpProxyToken
    {
        /// <summary>
        /// The stream for the connection
        /// </summary>
        public DataAdapterToStream Adapter { get; set; }

        /// <summary>
        /// Is this a CONNECT verb
        /// </summary>
        public bool Connect { get; private set; }

        /// <summary>
        /// The original HTTP request headers (minus request line)
        /// </summary>
        public string[] Headers { get; private set; }

        /// <summary>
        /// The URL associated with this connection
        /// </summary>
        public Uri Url { get; private set; }

        /// <summary>
        /// Somewhere to smuggle back the response from a HTTP proxy client (for CONNECT)
        /// </summary>
        public byte[] Response { get; set; }

        /// <summary>
        /// Indicates that the client is also to a HTTP proxy (stop the server transforming data)
        /// </summary>
        public bool IsHTTPProxyClient { get; set; }

        public HttpProxyToken(string hostname, int port, bool connect, string[] headers, Uri url, DataAdapterToStream adapter)
            : base(null, hostname, port, IpClientType.Tcp, false)
        {
            Connect = connect;
            Headers = headers;
            Url = url;
            Adapter = adapter;
        }

        protected override void OnDispose(bool finalize)
        {
            base.OnDispose(finalize);

            if (Adapter != null)
            {
                try
                {
                    Adapter.Dispose();
                }
                catch (Exception ex)
                {
                    Logger.SystemLogger.LogException(ex);
                }

                Adapter = null;
            }
        }

        public override void PopulateBag(PropertyBag properties)
        {
            base.PopulateBag(properties);

            properties.AddValue("Url", Url);
            properties.AddValue("Headers", Headers);
        }
    }
}
