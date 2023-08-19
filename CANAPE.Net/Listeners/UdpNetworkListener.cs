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
using CANAPE.Net.DataAdapters;
using CANAPE.Net.Utils;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace CANAPE.Net.Listeners
{
    /// <summary>
    /// This class implements a mechanism to multiplex connections to UDP sockets (which are inherently stateless)
    /// </summary>
    public class UdpNetworkListener : INetworkListener
    {
        UdpClient _clientSocket;
        Dictionary<IPEndPoint, LockedQueue<byte[]>> _conns;
        IPEndPoint _localEndpoint;
        Logger _logger;
        bool _broadcast;
        IPAddress[] _multicastGroups;
        Task _receive_task;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bindAddress">The address to bind to</param>
        /// <param name="broadcast">Set whether the socket is broadcast enabled</param>
        /// <param name="multicastGroups">A list of multicast groups to join</param>
        /// <param name="logger">Logger to report errors to</param>
        public UdpNetworkListener(IPEndPoint bindAddress, IPAddress[] multicastGroups, bool broadcast, Logger logger)
        {
            _conns = new Dictionary<IPEndPoint, LockedQueue<byte[]>>();
            _logger = logger;
            _localEndpoint = bindAddress;
            _broadcast = broadcast;
            _multicastGroups = multicastGroups ?? new IPAddress[0];
            ReopenConnection();
            if (_localEndpoint.Port == 0)
            {
                _logger.LogInfo(Properties.Resources.UdpNetworkListener_AutoBind, _clientSocket.Client.LocalEndPoint);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="anyBind"></param>
        /// <param name="ipv6"></param>
        /// <param name="port"></param>
        /// <param name="broadcast"></param>
        /// <param name="logger"></param>
        public UdpNetworkListener(bool anyBind, bool ipv6, int port, bool broadcast, Logger logger)
            : this(TcpNetworkListener.BuildEndpoint(anyBind, ipv6, port), null, broadcast, logger)
        {
        }

        /// <summary>
        /// Constructor, bind to a random port
        /// </summary>
        /// <param name="anyBind"></param>
        /// <param name="ipv6"></param>
        /// <param name="broadcast"></param>
        /// <param name="logger"></param>
        public UdpNetworkListener(bool anyBind, bool ipv6, bool broadcast, Logger logger)
            : this(anyBind, ipv6, 0, broadcast, logger)
        {
        }

        private void ReopenConnection()
        {
            if (_clientSocket != null)
            {
                try
                {
                    _clientSocket.Dispose();
                }
                catch (SocketException)
                {
                }
            }
            _clientSocket = new UdpClient();
            _clientSocket.Client.Bind(_localEndpoint);
            _clientSocket.EnableBroadcast = _broadcast;
            foreach (IPAddress addr in _multicastGroups)
            {
                _clientSocket.JoinMulticastGroup(addr);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ep"></param>
        /// <returns></returns>
        public byte[] Read(IPEndPoint ep)
        {
            lock (_conns)
            {
                if (!_conns.ContainsKey(ep))
                {
                    throw new ArgumentException(CANAPE.Net.Properties.Resources.UdpNetworkListener_NoUdpConnection);
                }
            }

            return _conns[ep].Dequeue();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ep"></param>
        public void CloseConnection(IPEndPoint ep)
        {
            lock (_conns)
            {
                if (_conns.ContainsKey(ep))
                {
                    _conns.Remove(ep);
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="ep"></param>
        public void Write(byte[] data, IPEndPoint ep)
        {
            _clientSocket.SendAsync(data, data.Length, ep).Wait();
        }

        private async Task ReceiveCallback()
        {
            while (true)
            {
                try
                {
                    var result = await _clientSocket.ReceiveAsync();
                    bool bNewConnection = false;
                    IPEndPoint ep = result.RemoteEndPoint;

                    lock (_conns)
                    {
                        if (!_conns.ContainsKey(result.RemoteEndPoint))
                        {
                            _logger.LogVerbose(Properties.Resources.UdpNetworkListener_ConnectionLogString, ep);
                            _conns.Add(ep, new LockedQueue<byte[]>());
                            bNewConnection = true;
                        }
                    }

                    _conns[ep].Enqueue(result.Buffer);
                    if (bNewConnection && (ClientConnected != null))
                    {
                        ClientConnectedEventArgs args =
                            new ClientConnectedEventArgs(new UdpServerDataAdapter(this, ep));
                        NetUtils.PopulateBagFromSocket(_clientSocket.Client, args.Properties);
                        ClientConnected.Invoke(this, args);
                    }
                }
                catch (SocketException ex)
                {
                    // For a server this just means the thing we last sent to ignored us
                    // Should possibly reopen the connection?
                    if (ex.SocketErrorCode == SocketError.ConnectionReset)
                    {
                        ReopenConnection();
                    }
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
            }
        }

        /// <summary>
        /// Start the listener
        /// </summary>
        public void Start()
        {
            if (_receive_task == null)
            {
                _receive_task = ReceiveCallback();
            }
        }

        /// <summary>
        /// Stop the listener
        /// </summary>
        public void Stop()
        {
            if (_receive_task != null)
            {
                lock (_conns)
                {
                    foreach (KeyValuePair<IPEndPoint, LockedQueue<byte[]>> pair in _conns)
                    {
                        pair.Value.Stop();
                    }
                }

                Task receive_task = _receive_task;
                _receive_task = null;

                try
                {
                    _clientSocket.Dispose();
                }
                catch
                {
                }
                finally
                {
                    // Wait for completion.
                    receive_task.Wait(1000);
                }

            }
        }

        /// <summary>
        /// Event called when a client connects
        /// </summary>
        public event EventHandler<ClientConnectedEventArgs> ClientConnected;

        /// <summary>
        /// Dispose the object
        /// </summary>
        public void Dispose()
        {
            try
            {
                Stop();
            }
            catch (SocketException)
            {
            }
        }

        /// <summary>
        /// Implements ToString
        /// </summary>
        /// <returns>Description of listener</returns>
        public override string ToString()
        {
            return String.Format(Properties.Resources.IpNetworkListener_ToStringFormat, "UDP", _localEndpoint);
        }
    }
}
