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
using System;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// An enumeration which indicates how to bind network layers, this is advisory and can be ignored by implementations
    /// </summary>
    [Flags]
    public enum NetworkLayerBinding
    {
        /// <summary>
        /// The default binding, what ever the network choses as it default
        /// </summary>
        Default = 0,
        /// <summary>
        /// Binds client only layer
        /// </summary>
        Client = 1,
        /// <summary>
        /// Binds server only layer
        /// </summary>
        Server = 2,
        /// <summary>
        /// Binds client and server layers
        /// </summary>
        ClientAndServer = Client | Server
    }
}
