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

namespace CANAPE.Net.Servers
{
    /// <summary>
    /// Base interface for a listening proxy
    /// </summary>
    public abstract class ProxyServer
    {
        /// <summary>
        /// Logger instance
        /// </summary>
        protected Logger _logger;

        /// <summary>
        /// Protected constructor
        /// </summary>
        /// <param name="logger"></param>
        protected ProxyServer(Logger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Accept a new proxy connection
        /// </summary>
        /// <param name="adapter">The data adapter to use</param>
        /// <param name="globalMeta">Global meta object</param>
        /// <param name="meta">Meta object</param>
        /// <param name="service">The service which contains this server</param>
        /// <returns>A object which implements IProxyToken</returns>
        public abstract ProxyToken Accept(IDataAdapter adapter, MetaDictionary meta, MetaDictionary globalMeta, ProxyNetworkService service);

        /// <summary>
        /// Complete the proxy connection by passing back the token and getting a new IDataAdapter
        /// </summary>
        /// <param name="token">The token returned from client</param>
        /// <param name="globalMeta">Global meta object</param>
        /// <param name="meta">Meta object</param>
        /// <param name="service">The service which contains this server</param>
        /// <param name="client">The client adapter which was created</param>
        /// <returns>The final data adapter, should be used for further work</returns>
        public abstract IDataAdapter Complete(ProxyToken token, MetaDictionary meta, MetaDictionary globalMeta, ProxyNetworkService service, IDataAdapter client);
    }
}
