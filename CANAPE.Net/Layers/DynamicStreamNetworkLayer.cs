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
using CANAPE.Utils;
using System.IO;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// A network layer based on a streams
    /// </summary>
    public abstract class DynamicStreamNetworkLayer : WrappedNetworkLayer<DynamicConfigObject, dynamic>
    {
        /// <summary>
        /// Method to implement for taking stream data
        /// </summary>
        /// <param name="clientStream"></param>
        /// <param name="serverStream"></param>
        /// <param name="binding"></param>
        /// <returns></returns>
        protected abstract bool OnConnect(Stream clientStream, Stream serverStream, NetworkLayerBinding binding);

        /// <summary>
        /// Method called on Connect
        /// </summary>
        /// <param name="client">The client adapter</param>
        /// <param name="server">The server adapter</param>
        /// <param name="binding">Binding mode</param>
        protected override sealed bool OnConnect(IDataAdapter client, IDataAdapter server, NetworkLayerBinding binding)
        {
            return OnConnect(new DataAdapterToStream(client), new DataAdapterToStream(server), binding);
        }
    }
}
