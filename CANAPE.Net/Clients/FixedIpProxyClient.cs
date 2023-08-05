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
using CANAPE.Net.Tokens;
using CANAPE.Nodes;
using CANAPE.Utils;

namespace CANAPE.Net.Clients
{
    /// <summary>
    /// An IP client which only goes to a fixed location
    /// </summary>
    public class FixedIpProxyClient : IpProxyClient
    {
        private readonly string _hostname;
        private readonly int _port;
        private readonly bool _ipv6;
        private readonly IpProxyToken.IpClientType _clientType;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="hostname">The hostname to connect to</param>
        /// <param name="port">The port to connect to</param>
        /// <param name="clientType">The type of connection to make</param>
        /// <param name="ipv6">Indicates whether to use ipv6</param>
        public FixedIpProxyClient(string hostname, int port, IpProxyToken.IpClientType clientType, bool ipv6)
        {
            _hostname = hostname;
            _port = port;
            _ipv6 = ipv6;
            _clientType = clientType;
        }

        /// <summary>
        /// Connect to the required service with the token
        /// </summary> 
        /// <param name="token">The token recevied from proxy</param>
        /// <param name="globalMeta">The global meta</param>
        /// <param name="logger">The logger</param>
        /// <param name="meta">The meta</param>
        /// <param name="properties">Property bag to add any information to</param>
        /// <returns>The connected data adapter</returns>
        public override IDataAdapter Connect(ProxyToken token, Logger logger, MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
        {
            // Just use the underlying code to do it for us
            return base.Connect(new IpProxyToken(null, _hostname, _port, _clientType, _ipv6), logger, meta, globalMeta, properties);
        }
    }
}
