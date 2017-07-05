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
using CANAPE.Net.Layers;
using CANAPE.Utils;

namespace CANAPE.Net.Templates.Factories
{
    /// <summary>
    /// Generic network layer factory.
    /// </summary>
    public sealed class GenericNetworkLayerFactory<T> : BaseNetworkLayerFactory 
                                                where T : INetworkLayer, new()
    {
        /// <summary>
        /// Creates the layer.
        /// </summary>
        /// <returns>The layer.</returns>
        /// <param name="logger">Logger.</param>
        public override INetworkLayer CreateLayer(Logger logger)
        {
            return new T();
        }
    }
}
