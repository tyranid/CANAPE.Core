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
using CANAPE.Net.Filters;
using CANAPE.Net.Listeners;
using CANAPE.Net.Servers;
using CANAPE.Net.Templates.Factories;
using CANAPE.Net.Utils;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;

namespace CANAPE.Net.Templates
{
    /// <summary>
    /// Document to represent a generic proxy
    /// </summary>
    public abstract class GenericProxyTemplate : ServiceTemplate
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public GenericProxyTemplate()
            : base()
        {            
            LocalPort = 1080;
            Filters = new ProxyFilterFactory[0];
            Client = new IpProxyClientFactory();
        }

        /// <summary>
        /// Method to create a proxy server
        /// </summary>
        /// <param name="logger">The logger to use</param>
        /// <returns>The proxy server</returns>
        protected abstract ProxyServer CreateServer(Logger logger);

        /// <summary>
        /// Method to create a network service
        /// </summary>
        /// <param name="logger">The logger to use</param>
        /// <returns>The network service</returns>
        /// <exception cref="NetServiceException">Thrown in configuration invalid</exception>
        public override ProxyNetworkService Create(Logger logger)
        {
            ProxyNetworkService ret = null;

            if (logger == null)
            {
                throw new ArgumentNullException("logger");
            }

            if ((LocalPort < 0) || (LocalPort > 65535))
            {
                throw new NetServiceException(Properties.Resources.GenericProxyDocument_MustSpecifyAValidPort);
            }
            else 
            {
                try
                {
                    List<ProxyFilter> filters = new List<ProxyFilter>();

                    foreach (ProxyFilterFactory item in Filters)
                    {
                        filters.Add(item.CreateFilter());
                    }

                    ProxyServer server = CreateServer(logger);
                    ProxyClient client = null;

                    if (Client != null)
                    {
                        client = Client.Create(logger);
                    }
                    else
                    {
                        client = new IpProxyClient();
                    }

                    INetworkListener listener = null;

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

                    if (listener == null)
                    {
                        throw new NetServiceException(CANAPE.Net.Templates.Properties.Resources.NetServiceDocument_CannotSetupListener);
                    }

                    ret = new ProxyNetworkService(listener,
                        Graph ?? BuildDefaultProxyFactory(), logger, _globalMeta,
                        server, client, filters.ToArray(), Timeout.Infinite, false);

                    ret.DefaultBinding = CANAPE.Net.Layers.NetworkLayerBinding.ClientAndServer;
                }
                catch (SocketException ex)
                {
                    throw new NetServiceException(Properties.Resources.GenericProxyDocument_ErrorCreatingService, ex);
                }
                catch (IOException ex)
                {
                    throw new NetServiceException(Properties.Resources.GenericProxyDocument_ErrorCreatingService, ex);
                }

                return ret;
            }
        }

        /// <summary>
        /// Get or set whether to bind to global address
        /// </summary>
        public bool AnyBind { get; set; }

        /// <summary>
        /// Get or set whether to bind to IPv6
        /// </summary>
        public bool Ipv6Bind { get; set; }

        /// <summary>
        /// Get or set the local port
        /// </summary>
        public int LocalPort { get; set; }

        /// <summary>
        /// Get or set list of filters
        /// </summary>
        public ProxyFilterFactory[] Filters { get; set; }

        /// <summary>
        /// Add a filter to this service
        /// </summary>
        /// <param name="factory">The factory to add</param>
        public void AddFilter(ProxyFilterFactory factory)
        {
            Filters = AddFactory(factory, Filters);
        }

        /// <summary>
        /// Insert a filter into this factory
        /// </summary>
        /// <param name="factory">The factory to insert</param>
        /// <param name="index">The index of the factory</param>
        public void InsertFilter(int index, ProxyFilterFactory factory)
        {
            Filters = InsertFactory(index, factory, Filters);
        }

        /// <summary>
        /// Remove a filter by index
        /// </summary>
        /// <param name="index">The index to remove the layer at</param>
        public void RemoveFilterAt(int index)
        {
            Filters = RemoveFactoryAt(index, Filters);
        }

        /// <summary>
        /// Remove a filter
        /// </summary>
        /// <param name="factory">The filter to remove</param>
        public void RemoveFilter(ProxyFilterFactory factory)
        {
            Filters = RemoveFactory(factory, Filters);
        }

        /// <summary>
        /// Get or set proxy client
        /// </summary>
        public IProxyClientFactory Client { get; set; }
    }
}
