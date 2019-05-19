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
using CANAPE.Net.Clients;
using CANAPE.Net.Layers;
using CANAPE.Net.Listeners;
using CANAPE.Net.Servers;
using CANAPE.Net.Templates.Factories;
using CANAPE.Net.Tokens;
using CANAPE.Net.Utils;
using CANAPE.Utils;
using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;

namespace CANAPE.Net.Templates
{
    /// <summary>
    /// Document to represent a fixed proxy
    /// </summary>
    public class FixedProxyTemplate : ServiceTemplate
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public FixedProxyTemplate()
        {
            LocalPort = 10000;
            Port = 12345;
            Host = "127.0.0.1";
            UdpEnable = false;
            Client = new IpProxyClientFactory();
            Layers = new INetworkLayerFactory[0];
        }

        /// <summary>
        /// Get or set whether to bind to global address
        /// </summary>
        public bool AnyBind
        {
            get; set;
        }

        /// <summary>
        /// Get or set whether to bind to IPv6
        /// </summary>
        public bool Ipv6Bind
        {
            get; set;
        }

        /// <summary>
        /// Get or set whether to connect to an IPv6 host
        /// </summary>
        public bool Ipv6
        {
            get; set;
        }

        /// <summary>
        /// Get or set local port
        /// </summary>
        public int LocalPort
        {
            get; set;
        }

        /// <summary>
        /// Get or set remote port
        /// </summary>
        public int Port
        {
            get; set;
        }

        /// <summary>
        /// Get or set remote host
        /// </summary>
        public string Host
        {
            get; set;
        }

        /// <summary>
        /// Get layers
        /// </summary>
        public INetworkLayerFactory[] Layers
        {
            get; set;
        }

        /// <summary>
        /// Add a layer to this service
        /// </summary>
        /// <param name="factory">The factory to add</param>
        public void AddLayer(INetworkLayerFactory factory)
        {
            Layers = AddFactory(factory, Layers);
        }

        /// <summary>
        /// Add a layer to this service.
        /// </summary>
        /// <typeparam name="T">The network layer type to create.</typeparam>
        public void AddLayer<T>() where T : INetworkLayer, new()
        {
            AddLayer(new GenericNetworkLayerFactory<T>());
        }

        /// <summary>
        /// Insert a layer into this factory
        /// </summary>
        /// <param name="factory">The factory to insert</param>
        /// <param name="index">The index of the factory</param>
        public void InsertLayer(int index, INetworkLayerFactory factory)
        {
            Layers = InsertFactory(index, factory, Layers);
        }

        /// <summary>
        /// Remove a layer by index
        /// </summary>
        /// <param name="index">The index to remove the layer at</param>
        public void RemoveLayerAt(int index)
        {
            Layers = RemoveFactoryAt(index, Layers);
        }

        /// <summary>
        /// Remove a layer
        /// </summary>
        /// <param name="factory">The layer to remove</param>
        public void RemoveLayer(INetworkLayerFactory factory)
        {
            Layers = RemoveFactory(factory, Layers);
        }

        /// <summary>
        /// Get or set UDP
        /// </summary>
        public bool UdpEnable
        {
            get; set;
        }

        /// <summary>
        /// Get or set broadcast use for UDP
        /// </summary>
        public bool EnableBroadcast
        {
            get; set;
        }

        /// <summary>
        /// Get or set the client factory
        /// </summary>
        public IProxyClientFactory Client
        {
            get; set;
        }

        /// <summary>
        /// Method to create the network service
        /// </summary>
        /// <param name="logger">The logger to use</param>
        /// <returns>The network service</returns>
        /// <exception cref="NetServiceException">Thrown if invalid configuration</exception>
        public override ProxyNetworkService Create(Logger logger)
        {
            ProxyNetworkService ret = null;

            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            if ((Port <= 0) || (Port > 65535))
            {
                throw new NetServiceException(Properties.Resources.FixedProxyDocument_MustProvideValidPort);
            }
            else if ((LocalPort < 0) || (LocalPort > 65535))
            {
                throw new NetServiceException(Properties.Resources.FixedProxyDocument_MustProvideValidLocalPort);
            }
            else
            {
                try
                {
                    ProxyServer server = new FixedProxyServer(logger, Host, Port,
                        UdpEnable ? IpProxyToken.IpClientType.Udp : IpProxyToken.IpClientType.Tcp,
                        Ipv6, Layers);

                    ProxyClient client = Client != null ? Client.Create(logger) : new IpProxyClient();

                    INetworkListener listener = null;

                    if (UdpEnable)
                    {
                        if (NetUtils.OSSupportsIPv4)
                        {
                            listener = new UdpNetworkListener(AnyBind, false, LocalPort, EnableBroadcast, logger);
                        }

                        if (Ipv6Bind && NetUtils.OSSupportsIPv6)
                        {
                            INetworkListener ipv6Listener = new UdpNetworkListener(AnyBind, true, LocalPort, EnableBroadcast, logger);

                            if (listener != null)
                            {
                                listener = new AggregateNetworkListener(listener, ipv6Listener);
                            }
                            else
                            {
                                listener = ipv6Listener;
                            }
                        }
                    }
                    else
                    {
                        if (NetUtils.OSSupportsIPv4)
                        {
                            listener = new TcpNetworkListener(AnyBind, false, LocalPort, logger, false);
                        }

                        if (Ipv6Bind && NetUtils.OSSupportsIPv6)
                        {
                            INetworkListener ipv6Listener = new TcpNetworkListener(AnyBind, true, LocalPort, logger, false);

                            if (listener != null)
                            {
                                listener = new AggregateNetworkListener(listener, ipv6Listener);
                            }
                            else
                            {
                                listener = ipv6Listener;
                            }
                        }
                    }

                    if (listener == null)
                    {
                        throw new NetServiceException(Properties.Resources.NetServiceDocument_CannotSetupListener);
                    }

                    ret = new ProxyNetworkService(listener,
                        Graph ?? BuildDefaultProxyFactory(), logger, _globalMeta,
                        server, client, null, Timeout.Infinite, false);

                    ret.DefaultBinding = NetworkLayerBinding.ClientAndServer;
                }
                catch (SocketException ex)
                {
                    throw new NetServiceException(Properties.Resources.FixedProxyDocument_ErrorCreatingService, ex);
                }
                catch (IOException ex)
                {
                    throw new NetServiceException(Properties.Resources.FixedProxyDocument_ErrorCreatingService, ex);
                }

                return ret;
            }
        }

        /// <summary>
        /// Overridden method to get description of service
        /// </summary>
        /// <returns>The description</returns>
        public override string ToString()
        {
            return string.Format(Properties.Resources.FixedProxyDocument_ToString,
                "", UdpEnable ? "UDP" : "TCP", LocalPort, Host, Port);
        }
    }
}
