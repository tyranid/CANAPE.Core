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
using CANAPE.Net.Layers;
using CANAPE.Net.Tokens;
using CANAPE.NodeFactories;
using CANAPE.Utils;
using System.Collections.Generic;

namespace CANAPE.Net.Filters
{
    /// <summary>
    /// Basic class for filtering proxy connections
    /// </summary>
    public class ProxyFilter
    {
        /// <summary>
        /// A netgraph to use for this connection (if null then use the default)
        /// </summary>
        public NetGraphFactory Graph { get; set; }

        /// <summary>
        /// A proxy client to use for this connection (if null then use default)
        /// </summary>
        public ProxyClient Client { get; set; }

        /// <summary>
        /// Array of network layers to apply to this connection on a match
        /// </summary>
        public INetworkLayerFactory[] Layers { get; set; }

        /// <summary>
        /// Policy for how layers are merged together
        /// </summary>
        public LayerMergePolicy MergePolicy { get; set; }

        /// <summary>
        /// Indicates this filter should block the matched connection
        /// </summary>
        public bool Block { get; set; }

        /// <summary>
        /// Indicates this filter is currently disabled
        /// </summary>
        public bool Disabled { get; set; }

        /// <summary>
        /// Indicates this filter will only match bound tokens
        /// </summary>
        public bool Bound { get; set; }

        /// <summary>
        /// Overridable method to determine if this token matches
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public virtual bool Match(ProxyToken token)
        {
            return token.Bind == Bound;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <param name="logger"></param>
        public virtual void Apply(ProxyToken token, Logger logger)
        {
            token.Status = Block ? NetStatusCodes.Blocked : NetStatusCodes.Success;
            token.Graph = Graph;
            token.Client = Client;

            List<INetworkLayer> layers = new List<INetworkLayer>(Layers.CreateLayers(logger));

            if (token.Layers != null)
            {
                switch (MergePolicy)
                {
                    case LayerMergePolicy.Prefix:
                        layers.AddRange(token.Layers);
                        break;
                    case LayerMergePolicy.Suffix:
                        layers.InsertRange(0, token.Layers);
                        break;
                    default:
                        // Do nothing
                        break;
                }
            }

            token.Layers = layers.ToArray();
        }
    }
}
