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
using CANAPE.Net.Clients;
using CANAPE.Net.Layers;
using CANAPE.Net.Listeners;
using CANAPE.Net.Servers;
using CANAPE.Net.Templates.Factories;
using CANAPE.Net.Tokens;
using CANAPE.Net.Utils;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;

namespace CANAPE.Net.Templates
{
    /// <summary>
    /// A document representing a network server
    /// </summary>
    public class NetServerTemplate<T, C> : ServiceTemplate
            where T : IDataEndpoint, IPersistNode, new() where C : new()
    {
        private class NetServerProxyClient : ProxyClient
        {
            DataEndpointFactory<T, C> _factory;

            public NetServerProxyClient(DataEndpointFactory<T, C> factory)
            {
                _factory = factory;
            }

            public override IDataAdapter Connect(ProxyToken token, Logger logger, MetaDictionary meta,
                MetaDictionary globalMeta, PropertyBag properties)
            {
                return new DataEndpointAdapter(_factory.Create(logger, meta, globalMeta), logger);
            }

            public override IDataAdapter Bind(ProxyToken token, Logger logger, MetaDictionary meta,
                MetaDictionary globalMeta, PropertyBag properties)
            {
                return null;
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public NetServerTemplate()
        {
            LocalPort = 12345;
            UdpEnable = false;
            Layers = new List<INetworkLayerFactory>();
            ServerFactory = new DataEndpointFactory<T, C>();
        }

        /// <summary>
        /// Create the base service
        /// </summary>
        /// <param name="logger">The logger to use</param>
        /// <returns>The new network service</returns>
        public override ProxyNetworkService Create(Logger logger)
        {
            ProxyNetworkService ret = null;

            if (logger == null)
            {
                logger = Logger.SystemLogger;
            }

            if ((LocalPort < 0) || (LocalPort > 65535))
            {
                throw new NetServiceException(Properties.Resources.NetServerDocument_ValidPort);
            }
            else if (ServerFactory == null)
            {
                throw new NetServiceException(Properties.Resources.NetServerDocument_MustSpecifyServer);
            }
            else
            {
                try
                {
                    ProxyServer server = new PassThroughProxyServer(logger, Layers);

                    ProxyClient client = new NetServerProxyClient(ServerFactory);

                    INetworkListener listener = null;

                    if (!UdpEnable)
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
                    else
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

                    if (listener == null)
                    {
                        throw new NetServiceException(Properties.Resources.NetServiceDocument_CannotSetupListener);
                    }

                    ret = new ProxyNetworkService(listener,
                        Graph ?? BuildDefaultProxyFactory(), logger, _globalMeta,
                        server, client, null, Timeout.Infinite, false);

                    ret.DefaultBinding = NetworkLayerBinding.Server;
                }
                catch (SocketException ex)
                {
                    throw new NetServiceException(Properties.Resources.NetServerDocument_ErrorCreatingServer, ex);
                }
                catch (IOException ex)
                {
                    throw new NetServiceException(Properties.Resources.NetServerDocument_ErrorCreatingServer, ex);
                }

                return ret;
            }
        }

        /// <summary>
        /// Get or set whether to bind globally
        /// </summary>
        public bool AnyBind { get; set; }

        /// <summary>
        /// Get or set whether to bind to IPv6
        /// </summary>
        public bool Ipv6Bind { get; set; }

        /// <summary>
        /// Get or set service port
        /// </summary>
        public int LocalPort { get; set; }

        /// <summary>
        /// Get or set list of layers
        /// </summary>
        public List<INetworkLayerFactory> Layers { get; private set; }

        /// <summary>
        /// Get or set whether to use UDP
        /// </summary>
        public bool UdpEnable { get; set; }

        /// <summary>
        /// Get or set whether to enable broadcast packets in UDP
        /// </summary>
        public bool EnableBroadcast { get; set; }

        /// <summary>
        /// Gets the server factory.
        /// </summary>
        /// <value>The server factory.</value>
        public DataEndpointFactory<T, C> ServerFactory { get; private set; }

        /// <summary>
        /// Gets the server factory config.
        /// </summary>
        /// <value>The server factory config.</value>
        public C ServerFactoryConfig { get { return ServerFactory.Config; } }

        /// <summary>
        /// Add a layer to this service
        /// </summary>
        /// <param name="factory">The factory to add</param>
        public void AddLayer(INetworkLayerFactory factory)
        {
            Layers.Add(factory);
        }

        /// <summary>
        /// Add a layer to this service.
        /// </summary>
        /// <typeparam name="L">The network layer type to create.</typeparam>
        public void AddLayer<L>() where L : INetworkLayer, new()
        {
            AddLayer(new GenericNetworkLayerFactory<L>());
        }

        /// <summary>
        /// Overridden method to get a description of server
        /// </summary>
        /// <returns>The description</returns>
        public override string ToString()
        {
            return String.Format("{0} - {1} server listening on port {2}", "", UdpEnable ? "UDP" : "TCP", LocalPort);
        }
    }
}
