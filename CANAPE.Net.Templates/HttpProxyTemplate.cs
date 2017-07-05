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
using CANAPE.Net.Servers;
using CANAPE.Utils;
using System;

namespace CANAPE.Net.Templates
{
    /// <summary>
    /// Document representing a HTTP proxy
    /// </summary>
    public class HttpProxyTemplate : GenericProxyTemplate
    {
        /// <summary>
        /// HTTP configuration
        /// </summary>
        protected HttpProxyServerConfig _config;

        /// <summary>
        /// Constructor
        /// </summary>
        public HttpProxyTemplate()
        {
            LocalPort = 3128;
            _config = new HttpProxyServerConfig();
        }

        /// <summary>
        /// Create the proxy server
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        protected override ProxyServer CreateServer(Logger logger)
        {
            return new FullHttpProxyServer(_config, logger);
        }

        /// <summary>
        /// Overridden ToString method
        /// </summary>
        /// <returns>The description of the service</returns>
        public override string ToString()
        {
            return String.Format(Properties.Resources.HttpProxyDocument_ToString, "", LocalPort);
        }

        /// <summary>
        /// The HTTP proxy server config
        /// </summary>
        public HttpProxyServerConfig Config
        {
            get { return _config; }
            set
            {
                if (_config != value)
                {
                    _config = value;
                }
            }
        }
    }
}
