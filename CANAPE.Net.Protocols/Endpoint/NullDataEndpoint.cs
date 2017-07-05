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
using CANAPE.Nodes;

namespace CANAPE.Net.Protocols.Endpoint
{
    /// <summary>
    /// Null data endpoint.
    /// </summary>
    public class NullDataEndpoint : BasePersistDataEndpoint<EchoDataEndpointConfig>
    {
        /// <summary>
        /// Run the specified adapter.
        /// </summary>
        /// <returns>The run.</returns>
        /// <param name="adapter">Adapter.</param>
        public override void Run(IDataAdapter adapter)
        {
            while (adapter.Read() != null)
            {
                // Do not alot
            }
        }

        /// <summary>
        /// Gets the description.
        /// </summary>
        /// <value>The description.</value>
        public override string Description
        {
            get { return "Null Endpoint"; }
        }
    }
}
