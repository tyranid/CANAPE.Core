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
using CANAPE.Net.Templates.Factories;
using CANAPE.Net.Tokens;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;

namespace CANAPE.Net.Templates
{
    /// <summary>
    /// Net client template.
    /// </summary>
    public sealed class NetClientTemplate
    {
        List<INetworkLayerFactory> _layers;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.Net.Templates.NetClientTemplate"/> class.
        /// </summary>
        public NetClientTemplate()
        {
            Port = 12345;
            Host = "127.0.0.1";
            _layers = new List<INetworkLayerFactory>();
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
        public IEnumerable<INetworkLayerFactory> Layers
        {
            get { return _layers.AsReadOnly(); }
        }

        /// <summary>
        /// Add a layer to this service
        /// </summary>
        /// <param name="factory">The factory to add</param>
        public void AddLayer(INetworkLayerFactory factory)
        {
            _layers.Add(factory);
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
            _layers.Insert(index, factory);
        }

        /// <summary>
        /// Remove a layer by index
        /// </summary>
        /// <param name="index">The index to remove the layer at</param>
        public void RemoveLayerAt(int index)
        {
            _layers.RemoveAt(index);
        }

        /// <summary>
        /// Remove a layer
        /// </summary>
        /// <param name="factory">The layer to remove</param>
        public void RemoveLayer(INetworkLayerFactory factory)
        {
            _layers.Remove(factory);
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
        /// Gets or sets a value indicating whether this <see cref="T:CANAPE.Net.Templates.NetClientTemplate"/> uses IPv6.
        /// </summary>
        /// <value><c>true</c> if IPv6; otherwise, <c>false</c>.</value>
        public bool IPv6
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the initial client data.
        /// </summary>
        /// <value>The initial client data.</value>
        public byte[] InitialData
        {
            get; set;
        }

        /// <summary>
        /// Connect this instance.
        /// </summary>
        /// <returns>The connected data adapter</returns>
        public IDataAdapter Connect()
        {
            return Connect(Logger.SystemLogger);
        }

        /// <summary>
        /// Connect this instance.
        /// </summary>
        /// <param name="logger">Logger object</param>
        /// <returns>The connected data adapter</returns>
        public IDataAdapter Connect(Logger logger)
        {
            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            if ((Port <= 0) || (Port > 65535))
            {
                throw new NetServiceException(Properties.Resources.FixedProxyDocument_MustProvideValidPort);
            }

            try
            {
                ProxyClient client = Client != null ? Client.Create(logger)
                                                            : new IpProxyClient();
                IpProxyToken token = new IpProxyToken(null, Host, Port,
                                                      UdpEnable ? IpProxyToken.IpClientType.Udp : IpProxyToken.IpClientType.Tcp, IPv6);
                IDataAdapter adapter = client.Connect(token, logger, new MetaDictionary(), new MetaDictionary(), new PropertyBag());
                if (_layers.Count > 0)
                {
                    MemoryStream initial_stm = new MemoryStream(InitialData ?? new byte[0]);
                    StreamDataAdapter initial = new StreamDataAdapter(initial_stm);
                    IDataAdapter client_adapter = initial;
                    foreach (INetworkLayer layer in _layers.Select(f => f.CreateLayer(logger)))
                    {
                        layer.Negotiate(ref client_adapter, ref adapter, token, logger, new MetaDictionary(),
                                        new MetaDictionary(), new PropertyBag(), NetworkLayerBinding.Client);
                    }
                }
                return adapter;
            }
            catch (SocketException ex)
            {
                throw new NetServiceException(Properties.Resources.FixedProxyDocument_ErrorCreatingService, ex);
            }
            catch (IOException ex)
            {
                throw new NetServiceException(Properties.Resources.FixedProxyDocument_ErrorCreatingService, ex);
            }
        }
    }
}
