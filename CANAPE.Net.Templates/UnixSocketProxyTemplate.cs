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
using CANAPE.Net.Utils;
using CANAPE.Utils;
using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;

namespace CANAPE.Net.Templates
{
    /// <summary>
    /// Template to represent a UNIX socket proxy.
    /// </summary>
    public class UnixSocketProxyTemplate : ServiceTemplate
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public UnixSocketProxyTemplate()
        {
            ListenPath = string.Empty;
            ConnectPath = string.Empty;
            Layers = new INetworkLayerFactory[0];
        }

        /// <summary>
        /// Get or set the listening UNIX socket path.
        /// </summary>
        public string ListenPath
        {
            get; set;
        }

        /// <summary>
        /// Get or set the connecting UNIX socket path.
        /// </summary>
        public string ConnectPath
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
        /// Method to create the network service
        /// </summary>
        /// <param name="logger">The logger to use</param>
        /// <returns>The network service</returns>
        /// <exception cref="NetServiceException">Thrown if invalid configuration</exception>
        public override ProxyNetworkService Create(Logger logger)
        {
            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            if (string.IsNullOrEmpty(ListenPath))
            {
                throw new NetServiceException(Properties.Resources.UnixSocketProxyTemplate_InvalidListenPath);
            }

            if (string.IsNullOrEmpty(ConnectPath))
            {
                throw new NetServiceException(Properties.Resources.UnixSocketProxyTemplate_InvalidConnectPath);
            }

            try
            {
                var server = new PassThroughProxyServer(logger, Layers);
                var client = new FixedStreamSocketProxyClient(new UnixEndPoint(ConnectPath), 0);
                if (File.Exists(ListenPath))
                {
                    File.Delete(ListenPath);
                }
                var listener = new StreamSocketNetworkListener(new UnixEndPoint(ListenPath), 0, logger);

                return new ProxyNetworkService(listener,
                    Graph ?? BuildDefaultProxyFactory(), logger, _globalMeta,
                    server, client, null, Timeout.Infinite, false)
                {
                    DefaultBinding = NetworkLayerBinding.ClientAndServer
                };
            }
            catch (SocketException ex)
            {
                throw new NetServiceException(Properties.Resources.UnixSocketProxyTemplate_ErrorCreatingProxy, ex);
            }
            catch (IOException ex)
            {
                throw new NetServiceException(Properties.Resources.UnixSocketProxyTemplate_ErrorCreatingProxy, ex);
            }
        }

        /// <summary>
        /// Overridden method to get description of service
        /// </summary>
        /// <returns>The description</returns>
        public override string ToString()
        {
            return string.Format(Properties.Resources.UnixSocketProxyTemplate_ToString,
                ListenPath, ConnectPath);
        }
    }
}
