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
using CANAPE.Net.Tokens;
using CANAPE.Utils;
using System;

namespace CANAPE.Net.Templates.Factories
{
    /// <summary>
    /// Factory to create a fixed IP proxy client
    /// </summary>
    public class FixedIpProxyClientFactory : BaseProxyClientFactory
    {
        private string _hostname;
        private int _port;
        private bool _ipv6;
        private bool _udp;

        /// <summary>
        /// Get or set the hostname
        /// </summary>
        public string Hostname
        {
            get
            {
                return _hostname;
            }

            set
            {
                if (_hostname != value)
                {
                    _hostname = value;
                }
            }
        }

        /// <summary>
        /// Get or set the port
        /// </summary>
        public int Port
        {
            get
            {
                return _port;
            }

            set
            {
                if (_port != value)
                {
                    _port = value;
                }
            }
        }

        /// <summary>
        /// Get or set using IPv6
        /// </summary>
        public bool IPv6
        {
            get
            {
                return _ipv6;
            }

            set
            {
                if (_ipv6 != value)
                {
                    _ipv6 = value;
                }
            }
        }

        /// <summary>
        /// Get or set using UDP
        /// </summary>
        public bool Udp
        {
            get
            {
                return _udp;
            }

            set
            {
                if (_udp != value)
                {
                    _udp = value;
                }
            }
        }

        /// <summary>
        /// Method to create the client
        /// </summary>
        /// <param name="logger">The logger to use</param>
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

            return new FixedIpProxyClient(_hostname, _port, _udp ? IpProxyToken.IpClientType.Udp : IpProxyToken.IpClientType.Tcp, _ipv6);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public FixedIpProxyClientFactory()
        {
            _hostname = "www.contextis.co.uk";
            _port = 80;
        }
    }
}
