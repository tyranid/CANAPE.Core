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
using CANAPE.Net.Clients;
using CANAPE.Utils;
using System;

namespace CANAPE.Net.Templates.Factories
{
    /// <summary>
    /// Proxy client factory for a SOCKS proxy
    /// </summary>
    public class SocksProxyClientFactory : TcpProxyClientFactory
    {
        bool _v4;
        bool _sendHostname;

        /// <summary>
        /// Get or set whether to use V4 SOCKS
        /// </summary>
        public bool Version4
        {
            get
            {
                return _v4;
            }

            set
            {
                if (_v4 != value)
                {
                    _v4 = value;
                }
            }
        }

        /// <summary>
        /// Get or set whether to send the host name to the SOCKS server (if possible)
        /// </summary>
        public bool SendHostname
        {
            get
            {
                return _sendHostname;
            }

            set
            {
                if (_sendHostname != value)
                {
                    _sendHostname = value;
                }
            }
        }

        /// <summary>
        /// Create the proxy client
        /// </summary>
        /// <param name="logger">The service logger</param>
        /// <returns>The proxy client</returns>
        public override ProxyClient Create(Logger logger)
        {
            if (String.IsNullOrWhiteSpace(_hostname))
            {
                throw new ArgumentException("Must specify a hostname");
            }

            if ((_port <= 0) || (_port > 65535))
            {
                throw new ArgumentException("Must specify a valid port number");
            }

            return new SocksProxyClient(_hostname, _port, _ipv6, 
                _v4 ? SocksProxyClient.SupportedVersion.Version4 : SocksProxyClient.SupportedVersion.Version5, _sendHostname);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public SocksProxyClientFactory()
        {
            _hostname = "localhost";
            _port = 1080;
        }
    }
}
