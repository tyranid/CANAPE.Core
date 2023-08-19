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
using System.Collections.Generic;
using System.Linq;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// Extension methods for network layer factories
    /// </summary>
    public static class NetworkLayerFactoryExtensions
    {
        /// <summary>
        /// Create an array of layers from a list of factories
        /// </summary>
        /// <param name="layers">The list of layers</param>
        /// <param name="logger">Logger to use when creating</param>
        /// <returns>The list of network layers</returns>
        public static INetworkLayer[] CreateLayers(this IEnumerable<INetworkLayerFactory> layers, Logger logger)
        {
            if (layers != null)
            {
                return layers.Where(f => !f.Disabled).Select(f => f.CreateLayer(logger)).ToArray();
            }
            else
            {
                return new INetworkLayer[0];
            }
        }
    }
}
