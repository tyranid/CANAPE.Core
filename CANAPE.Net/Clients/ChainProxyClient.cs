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
using System;

namespace CANAPE.Net.Clients
{
    /// <summary>
    /// A proxy client which will try and connect with multiple different clients until one succeeds
    /// </summary>
    public class ChainProxyClient : ProxyClient
    {
        private ProxyClient[] _clients;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="clients">List of clients</param>
        public ChainProxyClient(params ProxyClient[] clients)
        {
            if (clients == null)
            {
                throw new ArgumentNullException("clients");
            }

            if (clients.Length == 0)
            {
                throw new ArgumentException();
            }

            _clients = clients;
        }

        /// <summary>
        /// Connect the client
        /// </summary>
        /// <param name="token">The proxy token</param>
        /// <param name="logger">The proxy logger instance</param>
        /// <param name="meta">The proxy meta data</param>
        /// <param name="globalMeta">The proxy global meta data</param>
        /// <param name="properties">The proxy property bag</param>
        /// <returns>The connected adapter</returns>
        public override IDataAdapter Connect(ProxyToken token, Logger logger, MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
        {
            IDataAdapter ret = null;

            for (int i = 0; i < _clients.Length; ++i)
            {
                ret = _clients[i].Connect(token, logger, meta, globalMeta, properties);

                if (ret != null)
                {
                    break;
                }
            }

            if ((ret == null) && (token.Status == NetStatusCodes.Success))
            {
                ret = new IpProxyClient().Connect(token, logger, meta, globalMeta, properties);
            }

            return ret;
        }

        /// <summary>
        /// Bind the client
        /// </summary>
        /// <param name="token">The proxy token</param>
        /// <param name="logger">The proxy logger instance</param>
        /// <param name="meta">The proxy meta data</param>
        /// <param name="globalMeta">The proxy global meta data</param>
        /// <param name="properties">The proxy property bag</param>
        /// <returns>The connected adapter</returns>
        public override IDataAdapter Bind(ProxyToken token, Logger logger, MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
        {
            return null;
        }
    }
}
