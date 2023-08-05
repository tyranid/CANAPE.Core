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
using CANAPE.Net.Layers;

namespace CANAPE.Net.Servers
{
    /// <summary>
    /// Configuration for HTTP proxy
    /// </summary>
    public class HttpProxyServerConfig
    {
        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="T:CANAPE.Net.Servers.HttpProxyServerConfig"/>
        /// version10 proxy.
        /// </summary>
        /// <value><c>true</c> if version10 proxy; otherwise, <c>false</c>.</value>
        public bool Version10Proxy
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the ssl config.
        /// </summary>
        /// <value>The ssl config.</value>
        public TlsNetworkLayerConfig SslConfig
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="T:CANAPE.Net.Servers.HttpProxyServerConfig"/>
        /// require auth.
        /// </summary>
        /// <value><c>true</c> if require auth; otherwise, <c>false</c>.</value>
        public bool RequireAuth { get; set; }

        /// <summary>
        /// Gets or sets the proxy username.
        /// </summary>
        /// <value>The proxy username.</value>
        public string ProxyUsername { get; set; }

        /// <summary>
        /// Gets or sets the proxy password.
        /// </summary>
        /// <value>The proxy password.</value>
        public string ProxyPassword { get; set; }

        /// <summary>
        /// Gets or sets the auth realm.
        /// </summary>
        /// <value>The auth realm.</value>
        public string AuthRealm { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="T:CANAPE.Net.Servers.HttpProxyServerConfig"/> debug log.
        /// </summary>
        /// <value><c>true</c> if debug log; otherwise, <c>false</c>.</value>
        public bool DebugLog { get; set; }


        /// <summary>
        /// Specify the number of times we will retry to connect a connection
        /// </summary>
        public int ConnectionRetries { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public HttpProxyServerConfig()
        {
            SslConfig = new TlsNetworkLayerConfig(true, false);
            ProxyUsername = "canape";
            ProxyPassword = "canape";
            AuthRealm = "canape.local";
            ConnectionRetries = 2;
        }
    }
}
