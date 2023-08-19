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
    /// Network listener implement for a TCP server
    /// TODO: Add two listeners for both v4 and v6 endpoints, maybe just make that the default?
    /// </summary>
    public class TcpNetworkListener : INetworkListener
    {
        Task _accept_task;
        TcpListener _listener;
        Logger _logger;
        List<TcpClient> _pending;
        bool _autoBind;
        bool _nodelay;

        /// <summary>
        /// Listener endpoint
        /// </summary>
        public IPEndPoint EndPoint { get { return (IPEndPoint)_listener.Server.LocalEndPoint; } }

        internal static IPEndPoint BuildEndpoint(bool anyBind, bool ipv6, int port)
        {
            if (ipv6)
            {
                return new IPEndPoint(anyBind ? IPAddress.IPv6Any : IPAddress.IPv6Loopback, port);
            }
            else
            {
                return new IPEndPoint(anyBind ? IPAddress.Any : IPAddress.Loopback, port);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bindAddress">The address to bind to</param>
        /// <param name="logger">Logger to report errors to</param>
        /// <param name="nodelay">Set whether the socket will have nagle algorithm disabled</param>
        public TcpNetworkListener(IPEndPoint bindAddress, Logger logger, bool nodelay)
        {
            _logger = logger;
            _listener = new TcpListener(bindAddress);
            _pending = new List<TcpClient>();

            if (bindAddress.Port == 0)
            {
                _autoBind = true;
            }

            _nodelay = nodelay;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="anyBind">True to bind to all addresses, otherwise just localhost</param>
        /// <param name="ipv6">Whether to use IPv6</param>
        /// <param name="port">The TCP port</param>
        /// <param name="logger">Logger to report errors to</param>
        /// <param name="nodelay">Set whether the socket will have nagle algorithm disabled</param>
        public TcpNetworkListener(bool anyBind, bool ipv6, int port, Logger logger, bool nodelay)
            : this(BuildEndpoint(anyBind, ipv6, port), logger, nodelay)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="anyBind">True to bind to all addresses, otherwise just localhost</param>
        /// <param name="ipv6">Whether to use IPv6</param>
        /// <param name="logger">Logger to report errors to</param>
        /// <param name="nodelay">Set whether the socket will have nagle algorithm disabled</param>
        public TcpNetworkListener(bool anyBind, bool ipv6, Logger logger, bool nodelay)
            : this(anyBind, ipv6, 0, logger, nodelay)
        {
        }

        private async Task SetupClient(TcpClient client)
        {
            lock (_pending)
            {
                _pending.Add(client);
            }

            _logger.LogVerbose(Properties.Resources.TcpNetworkListener_ConnectionLogString, client.Client.RemoteEndPoint);

            TcpClientDataAdapter da = new TcpClientDataAdapter(client);
            ClientConnectedEventArgs e = new ClientConnectedEventArgs(da);
            NetUtils.PopulateBagFromSocket(client.Client, e.Properties);

            try
            {
                await Task.Run(() => ClientConnected.Invoke(this, e));
            }
            catch
            {
                client.Dispose();
            }
            finally
            {
                lock (_pending)
                {
                    _pending.Remove(client);
                }
            }
        }

        private async Task AcceptCallback(TcpListener listener)
        {
            List<Task> pending_tasks = new List<Task>();
            while (true)
            {
                try
                {
                    pending_tasks.Add(listener.AcceptTcpClientAsync());
                    Task task = await Task.WhenAny(pending_tasks);
                    pending_tasks.Remove(task);

                    if (task is Task<TcpClient>)
                    {
                        TcpClient client = await (Task<TcpClient>)task;
                        client.NoDelay = _nodelay;
                        if (ClientConnected != null)
                        {
                            pending_tasks.Add(SetupClient(client));
                        }
                        else
                        {
                            // There was noone to accept the message, so just close
                            client.Dispose();
                        }
                    }
                }
                catch (ObjectDisposedException)
                {
                    // If client socket closed then exit loop.
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogException(ex);
                }
            }
        }

        /// <summary>
        /// Start the listener
        /// </summary>
        public void Start()
        {
            if (_accept_task == null)
            {
                _listener.Start();
                if (_autoBind)
                {
                    _logger.LogInfo(Properties.Resources.TcpNetworkListener_AutoBind, _listener.Server.LocalEndPoint);
                }
                _accept_task = AcceptCallback(_listener);
            }
        }

        /// <summary>
        /// Stop the listener
        /// </summary>
        public void Stop()
        {
            if (_accept_task != null)
            {
                Task accept_task = _accept_task;
                _accept_task = null;
                try
                {
                    _listener.Stop();
                    lock (_pending)
                    {
                        foreach (TcpClient client in _pending)
                        {
                            try
                            {
                                client.Dispose();
                            }
                            catch
                            {
                            }
                        }

                        _pending.Clear();
                    }
                    accept_task.Wait(1000);
                }
                catch (Exception ex)
                {
                    Logger.SystemLogger.LogException(ex);
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
            catch (ObjectDisposedException)
            {
            }
        }

        /// <summary>
        /// Implements ToString
        /// </summary>
        /// <returns>Description of listener</returns>
        public override string ToString()
        {
            return string.Format(Properties.Resources.IpNetworkListener_ToStringFormat, "TCP", _listener.LocalEndpoint);
        }
    }
}
