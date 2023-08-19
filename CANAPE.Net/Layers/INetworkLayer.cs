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
    /// An interface to describe a network layer negotiator
    /// </summary>
    public interface INetworkLayer
    {
        /// <summary>
        /// Method to negotiate the layer
        /// </summary>
        /// <param name="server">Reference to the server adapter, can change the adapter</param>
        /// <param name="client">Reference to the client adapter, can change the adapter</param>
        /// <param name="token">A token which is associated with this connection</param>
        /// <param name="logger">Logger object</param>
        /// <param name="globalMeta">Global meta dictionary</param>
        /// <param name="meta">Meta dictionary</param>
        /// <param name="properties">The property bag to add any connection information to</param>
        /// <param name="defaultBinding">Indicates the current default binding mode, layers are free to ignore (at their peril)</param>
        void Negotiate(ref IDataAdapter server, ref IDataAdapter client, ProxyToken token, Logger logger, MetaDictionary meta,
            MetaDictionary globalMeta, PropertyBag properties, NetworkLayerBinding defaultBinding);

        /// <summary>
        /// The binding mode for the layer if different from default
        /// </summary>
        NetworkLayerBinding Binding { get; set; }
    }
}
