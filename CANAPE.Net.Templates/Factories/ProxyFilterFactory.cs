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
using CANAPE.Net.Filters;
using CANAPE.Net.Layers;
using CANAPE.NodeFactories;

namespace CANAPE.Net.Templates.Factories
{
    /// <summary>
    /// A factory object for a filter 
    /// </summary>
    public abstract class ProxyFilterFactory 
    {        
        /// <summary>
        /// A netgraph to use for this connection (if null then use the default)
        /// </summary>
        public NetGraphFactory Graph { get; set; }

        /// <summary>
        /// A proxy client to use for this connection (if null then use default)
        /// </summary>
        public IProxyClientFactory Client { get; set; }

        /// <summary>
        /// List of layer factories
        /// </summary>
        public INetworkLayerFactory[] Layers { get; set; }

        /// <summary>
        /// Indicates this filter should block connection
        /// </summary>
        public bool Block { get; set; }

        /// <summary>
        /// Method to create the filter
        /// </summary>
        /// <returns></returns>
        protected abstract ProxyFilter OnCreateFilter();        

        /// <summary>
        /// Create the filter from the factory
        /// </summary>
        /// <returns></returns>
        public ProxyFilter CreateFilter()
        {
            ProxyFilter filter = OnCreateFilter();

            if (filter != null)
            {
                filter.Graph = Graph;
                if (Client != null)
                {
                    filter.Client = Client.Create(null);
                }
                if (Layers != null)
                {                    
                    filter.Layers = Layers;
                }
                filter.Block = Block;
            }

            return filter;
        }
    }
}
