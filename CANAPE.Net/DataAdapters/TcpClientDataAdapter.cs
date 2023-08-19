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
using System;
using System.Net.Sockets;

namespace CANAPE.DataAdapters
{
    /// <summary>
    /// Data adapter for a TCP client object
    /// </summary>
    public class TcpClientDataAdapter : StreamDataAdapter
    {
        TcpClient _clientSocket;

        /// <summary>
        /// Get the client socket associated with this adapter
        /// </summary>
        public TcpClient Socket { get { return _clientSocket; } }

        /// <summary>
        /// Construct the client data adapter
        /// </summary>
        /// <param name="clientSocket">The client socket object</param>
        /// <param name="description">Description of the adapter</param>
        public TcpClientDataAdapter(TcpClient clientSocket, string description) : base(clientSocket.GetStream())
        {
            _clientSocket = clientSocket;
            if (description != null)
            {
                Description = description;
            }
            else
            {
                Description = clientSocket.Client.RemoteEndPoint.ToString();
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="clientSocket">The socket</param>
        public TcpClientDataAdapter(TcpClient clientSocket)
            : this(clientSocket, null)
        {
        }

        /// <summary>
        /// Perform close
        /// </summary>
        protected override void OnDispose(bool disposing)
        {
            base.OnDispose(disposing);

            try
            {
                _clientSocket.Dispose();
            }
            catch (Exception ex)
            {
                Logger.SystemLogger.LogException(ex);
            }
        }
    }
}
