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
    /// General network listener for stream sockets.
    /// </summary>
    public class StreamSocketNetworkListener : INetworkListener
    {
        private Task _accept_task;
        private Socket _listener;
        private readonly Logger _logger;
        private readonly List<Socket> _pending;
        private readonly EndPoint _localEndpoint;
        private readonly ProtocolType _type;

        private async Task SetupClient(Socket client)
        {
            lock (_pending)
            {
                _pending.Add(client);
            }

            _logger.LogVerbose(Properties.Resources.TcpNetworkListener_ConnectionLogString, _localEndpoint);

            StreamSocketDataAdapter da = new StreamSocketDataAdapter(client, _localEndpoint.ToString());
            ClientConnectedEventArgs e = new ClientConnectedEventArgs(da);
            NetUtils.PopulateBagFromSocket(client, e.Properties);

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

        private async Task AcceptCallback(Socket listener)
        {
            List<Task> pending_tasks = new List<Task>();
            while (true)
            {
                try
                {
                    pending_tasks.Add(listener.AcceptAsync());
                    Task task = await Task.WhenAny(pending_tasks);
                    pending_tasks.Remove(task);

                    if (task is Task<Socket>)
                    {
                        Socket client = await (Task<Socket>)task;
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
        /// Client connected event.
        /// </summary>
        public event EventHandler<ClientConnectedEventArgs> ClientConnected;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="bindAddress">The address to bind to</param>
        /// <param name="type">The protocol type of the socket.</param>
        /// <param name="logger">Logger to report errors to</param>
        public StreamSocketNetworkListener(EndPoint bindAddress, ProtocolType type, Logger logger)
        {
            _localEndpoint = bindAddress;
            _type = type;
            _logger = logger;
            _pending = new List<Socket>();
        }

        /// <summary>
        /// Dispose the listener.
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
        /// Start the listener
        /// </summary>
        public void Start()
        {
            if (_listener != null)
            {
                return;
            }

            try
            {
                _listener = new Socket(_localEndpoint.AddressFamily, SocketType.Stream, _type);
                _listener.Bind(_localEndpoint);
                _listener.Listen(int.MaxValue);
                _accept_task = AcceptCallback(_listener);
            }
            catch
            {
                _listener?.Dispose();
                _listener = null;
                throw;
            }
        }

        /// <summary>
        /// Stop the listener
        /// </summary>
        public void Stop()
        {
            if (_listener != null)
            {
                Task accept_task = _accept_task;
                _accept_task = null;
                try
                {
                    _listener.Close();
                    _listener = null;
                    lock (_pending)
                    {
                        foreach (var client in _pending)
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
                    accept_task?.Wait(1000);
                }
                catch (Exception ex)
                {
                    Logger.SystemLogger.LogException(ex);
                }
            }
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The listener as a string.</returns>
        public override string ToString()
        {
            return string.Format(Properties.Resources.StreamSocketNetworkListener_ToString,
                _localEndpoint.AddressFamily, _localEndpoint);
        }
    }
}
