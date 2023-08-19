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

namespace CANAPE.Net.Layers
{
    /// <summary>
    ///Base network layer class, makes implementation slightly simpler
    /// </summary>
    public abstract class BaseNetworkLayer<T, R> : PersistNodeImpl<T, R>, INetworkLayer where R : class where T : class, R, new()
    {
        /// <summary>
        /// Proxy token for this connection
        /// </summary>
        protected ProxyToken Token { get; private set; }

        /// <summary>
        /// Logger for this connection
        /// </summary>
        protected Logger Logger { get; private set; }

        /// <summary>
        /// Meta data associated with this connection
        /// </summary>
        protected MetaDictionary Meta { get; private set; }

        /// <summary>
        /// Global meta data associated with this connection
        /// </summary>
        protected MetaDictionary GlobalMeta { get; private set; }

        /// <summary>
        /// Property bag associated with connection
        /// </summary>
        protected PropertyBag Properties { get; private set; }

        /// <summary>
        /// Current binding mode
        /// </summary>
        public NetworkLayerBinding Binding { get; set; }

        /// <summary>
        /// Called on layer setup, allows you to override the clients and server adapters if needed
        /// </summary>
        /// <param name="client">Reference to the client adapter</param>
        /// <param name="server">References to the server adapter</param>
        /// <param name="binding">The current binding</param>
        protected abstract void OnConnect(ref IDataAdapter client, ref IDataAdapter server, NetworkLayerBinding binding);

        /// <summary>
        /// Negotiate method
        /// </summary>
        /// <param name="server">Server adapter</param>
        /// <param name="client">Client adapter</param>
        /// <param name="token">The associated proxy token</param>
        /// <param name="logger">The associated logger</param>
        /// <param name="meta">The associated meta dictionary</param>
        /// <param name="globalMeta">The assocaited global meta dictionary</param>
        /// <param name="properties">Property bag</param>
        /// <param name="defaultBinding">Default layer binding mode</param>
        public void Negotiate(ref IDataAdapter server, ref IDataAdapter client, ProxyToken token, Logger logger,
            MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties, NetworkLayerBinding defaultBinding)
        {
            Token = token;
            Logger = logger;
            Meta = meta;
            GlobalMeta = globalMeta;
            Properties = properties;

            if (defaultBinding == NetworkLayerBinding.Default)
            {
                defaultBinding = NetworkLayerBinding.ClientAndServer;
            }

            if (Binding != NetworkLayerBinding.Default)
            {
                defaultBinding = Binding;
            }

            OnConnect(ref client, ref server, defaultBinding);
        }
    }
}
