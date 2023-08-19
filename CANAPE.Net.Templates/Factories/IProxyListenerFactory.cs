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
using CANAPE.Net.Listeners;
using CANAPE.Utils;

namespace CANAPE.Net.Templates.Factories
{
    /// <summary>
    /// Factory for creating a listener
    /// </summary>
    public interface IProxyListenerFactory
    {
        /// <summary>
        /// Create the network listener
        /// </summary>
        /// <param name="logger">The logger</param>
        /// <returns>The new network listener</returns>
        INetworkListener Create(Logger logger);
    }
}
