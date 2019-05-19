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
using CANAPE.Net.Utils;
using CANAPE.NodeFactories;
using CANAPE.Nodes;
using CANAPE.Utils;
using System.Collections.Generic;

namespace CANAPE.Net.Templates
{
    /// <summary>
    /// Implement the basics of the TCP service form configuration
    /// </summary>
    public abstract class ServiceTemplate
    {
        /// <summary>
        /// The global meta for the service, not saved as it could contain anything
        /// </summary>
        protected MetaDictionary _globalMeta;

        /// <summary>
        /// Constructor
        /// </summary>
        public ServiceTemplate()
        {
            _globalMeta = new MetaDictionary();
        }

        /// <summary>
        /// Net graph
        /// </summary>
        public NetGraphFactory Graph
        {
            get; set;
        }

        /// <summary>
        /// Get the global meta dictionary
        /// </summary>
        public MetaDictionary GlobalMeta
        {
            get { return _globalMeta; }
        }

        /// <summary>
        /// Method to create the network service based on the configuration
        /// </summary>
        /// <param name="logger">A logger to out the log data to</param>
        /// <returns></returns>
        public abstract ProxyNetworkService Create(Logger logger);

        /// <summary>
        /// Method to create the network service based on the configuration with default logger
        /// </summary>
        /// <returns>The network service</returns>
        public ProxyNetworkService Create()
        {
            return Create(Logger.SystemLogger);
        }

        /// <summary>
        /// Guild the default graph factory
        /// </summary>
        /// <returns>The graph factory</returns>
        protected static NetGraphFactory BuildDefaultProxyFactory()
        {
            return NetGraphBuilder.CreateDefaultProxyGraph();
        }

        internal static T[] AddFactory<T>(T factory, T[] factories)
        {
            List<T> fs = new List<T>(factories);

            fs.Add(factory);

            return fs.ToArray();
        }

        internal static T[] InsertFactory<T>(int index, T factory, T[] factories)
        {
            List<T> fs = new List<T>(factories);
            fs.Insert(index, factory);

            return fs.ToArray();
        }

        internal static T[] RemoveFactoryAt<T>(int index, T[] factories)
        {
            List<T> fs = new List<T>(factories);

            fs.RemoveAt(index);

            return fs.ToArray();
        }

        internal static T[] RemoveFactory<T>(T factory, T[] factories)
        {
            List<T> fs = new List<T>(factories);

            fs.Remove(factory);

            return fs.ToArray();
        }
    }
}
