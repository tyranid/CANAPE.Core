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
    /// Factory to create a HTTP proxy client
    /// </summary>
    public class HttpProxyClientFactory : TcpProxyClientFactory
    {
        private bool _requireAuthentication;
        private string _username;
        private string _password;
        private string _domain;

        /// <summary>
        /// Method to create the client
        /// </summary>
        /// <param name="logger">The logger to use</param>
        /// <returns>The proxy client</returns>
        /// <exception cref="ArgumentException">Throw if configuration invalid</exception>
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

            return new HttpProxyClient(_hostname, _port, _ipv6);
        }

        /// <summary>
        /// Indicates whether authentication is required
        /// </summary>
        public bool RequireAuthentication
        {
            get
            {
                return _requireAuthentication;
            }

            set
            {
                if (_requireAuthentication != value)
                {
                    _requireAuthentication = value;
                }
            }
        }

        /// <summary>
        /// Authentication username
        /// </summary>
        public string Username
        {
            get
            {
                return _username;
            }

            set
            {
                if (_username != value)
                {
                    _username = value;
                }
            }
        }

        /// <summary>
        /// Authentication username
        /// </summary>
        public string Password
        {
            get
            {
                return _password;
            }

            set
            {
                if (_password != value)
                {
                    _password = value;
                }
            }
        }

        /// <summary>
        /// Authentication domain
        /// </summary>
        public string Domain
        {
            get
            {
                return _domain;
            }

            set
            {
                if (_domain != value)
                {
                    _domain = value;
                }
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public HttpProxyClientFactory()
        {
            _hostname = "localhost";
            _port = 3128;
        }
    }
}
