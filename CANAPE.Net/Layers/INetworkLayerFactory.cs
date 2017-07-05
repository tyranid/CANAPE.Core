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
using CANAPE.Utils;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// A factory for a network layer
    /// </summary>
    public interface INetworkLayerFactory
    {
        /// <summary>
        /// Create an instance of the layer
        /// </summary>
        /// <param name="logger">A logger to use when creating the layer</param>
        /// <returns>The created layer</returns>
        INetworkLayer CreateLayer(Logger logger);

        /// <summary>
        /// Get a descriptive name for this layer factory
        /// </summary>
        string Description { get; set; }

        /// <summary>
        /// Get or set the network layer binding mode
        /// </summary>
        NetworkLayerBinding Binding { get; set; }

        /// <summary>
        /// Get or set layer is disabled
        /// </summary>
        bool Disabled { get; set; }

        /// <summary>
        /// Clone the factory
        /// </summary>
        /// <returns>The cloned factory</returns>
        INetworkLayerFactory Clone();
    }
}
