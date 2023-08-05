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
using System.Net.Sockets;

namespace CANAPE.Net.DataAdapters
{
    /// <summary>
    /// Data adapter for a stream socket.
    /// </summary>
    public class StreamSocketDataAdapter : StreamDataAdapter
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="client">The socket client.</param>
        /// <param name="description">The description for the data adapter.</param>
        public StreamSocketDataAdapter(Socket client, string description)
            : base(new NetworkStream(client, true), description)
        {
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="client">The socket client.</param>
        public StreamSocketDataAdapter(Socket client)
            : this(client, client.RemoteEndPoint.ToString())
        {
        }
    }
}
