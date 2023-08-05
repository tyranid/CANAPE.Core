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
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace CANAPE.Net.DataAdapters
{
    /// <summary>
    /// Bound data adapter backed by a TCP listener
    /// </summary>
    public class TcpListenerDataAdapter : IpBoundDataAdapter
    {
        TcpListener _listener;

        /// <summary>
        /// Get the listener
        /// </summary>
        public TcpListener Listener { get { return _listener; } }

        /// <summary>
        /// Get the listening endpoint
        /// </summary>
        public override IPEndPoint Endpoint
        {
            get { return (IPEndPoint)_listener.Server.LocalEndPoint; }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bindAddress">The bind endpoint address</param>
        public TcpListenerDataAdapter(IPEndPoint bindAddress)
        {
            _listener = new TcpListener(bindAddress);
            _listener.Start(1);
        }

        /// <summary>
        /// Do connection
        /// </summary>
        /// <param name="timeout">Timeout for connection in seconds</param>
        /// <returns>The connected adapter</returns>
        /// <exception cref="TimeoutException">Thrown if imeout</exception>
        protected override IDataAdapter DoConnect(int timeout)
        {
            IDataAdapter ret = null;

            try
            {
                List<Socket> readSockets = new List<Socket>();
                readSockets.Add(_listener.Server);
                List<Socket> errorSockets = new List<Socket>();
                errorSockets.Add(_listener.Server);

                Socket.Select(readSockets, null, errorSockets, timeout < 0 ? timeout : timeout * 1000);

                if (readSockets.Count > 0)
                {
                    ret = new TcpClientDataAdapter(_listener.AcceptTcpClientAsync().GetAwaiter().GetResult());
                }
                else
                {
                    throw new TimeoutException();
                }
            }
            finally
            {
                _listener.Stop();
            }

            return ret;
        }

        /// <summary>
        /// Dispose
        /// </summary>
        /// <param name="disposing">True if disposing</param>
        protected override void OnDispose(bool disposing)
        {
            try
            {
                _listener.Stop();
            }
            catch (SocketException)
            {
            }

            base.OnDispose(disposing);
        }
    }
}
