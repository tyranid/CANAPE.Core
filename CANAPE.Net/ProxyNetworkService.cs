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
using CANAPE.Net.Filters;
using CANAPE.Net.Layers;
using CANAPE.Net.Listeners;
using CANAPE.Net.Servers;
using CANAPE.Net.Tokens;
using CANAPE.Net.Utils;
using CANAPE.NodeFactories;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace CANAPE.Net
{
    /// <summary>
    /// Event arguments for a new connection
    /// </summary>
    public class ConnectionEventArgs : EventArgs
    {
        /// <summary>
        /// The newly connected graph
        /// </summary>
        public NetGraph Graph { get; private set; }

        /// <summary>
        /// Gets the network description.
        /// </summary>
        /// <value>The description of the network.</value>
        public string Description { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="graph"></param>
        public ConnectionEventArgs(NetGraph graph)
        {
            Graph = graph;
            Description = graph.NetworkDescription;
        }
    }

    /// <summary>
    /// Implementation of a proxy service
    /// </summary>
    public sealed class ProxyNetworkService
    {
        enum ServiceState
        {
            Stopped,
            RunPending,
            Running,
            StopPending
        }

        #region Private Variables        
        private int _state;
        private INetworkListener _listener;
        private NetGraphFactory _factory;
        private Logger _logger;
        private List<ConnectionEntry> _connections;
        private MetaDictionary _globalMeta;
        private List<LogPacket> _packetLog;
        private IList<ConnectionHistoryEntry> _history;
        private List<ProxyNetworkService> _subServices;
        private ProxyNetworkService _parentService;
        private ProxyServer _proxyServer;
        private ProxyClient _proxyClient;
        private ProxyFilter[] _filters;
        private int _defaultTimeout;
        private bool _afterData;
        #endregion

        /// <summary>
        /// ToString implementation
        /// </summary>
        /// <returns>Return the service information</returns>
        public override string ToString()
        {
            return String.Format(Properties.Resources.ProxyNetworkService_ToStringFormat, _listener, _proxyServer);
        }

        private sealed class ConnectionEntry : IDisposable
        {
            private ProxyNetworkService _service;
            private int _lastTimeout;
            private bool _timeoutAfterData;

            public NetGraph Graph { get; private set; }

            public Timer Timer { get; private set; }

            public void SetTimeout(int timeout, bool afterData)
            {
                if (!Graph.IsDisposed)
                {
                    if (Timer != null)
                    {
                        Timer.Change(timeout, Timeout.Infinite);
                    }
                    else
                    {
                        Timer = new Timer(ConnectionTimeout, null, timeout, Timeout.Infinite);
                    }

                    _lastTimeout = timeout;
                    _timeoutAfterData = afterData;
                }
            }

            private void ConnectionTimeout(object state)
            {
                _service.CloseConnection(this);
            }

            public ConnectionEntry(ProxyNetworkService service, NetGraph graph, int timeout, bool afterData)
            {
                _service = service;
                Graph = graph;

                if (timeout > 0)
                {
                    SetTimeout(timeout, afterData);
                }

                foreach (KeyValuePair<Guid, BasePipelineNode> node in graph.Nodes)
                {
                    IPipelineEndpoint ep = node.Value as IPipelineEndpoint;

                    if (ep != null)
                    {
                        ep.DataRecieved += ep_DataRecieved;
                    }
                }
            }

            void ep_DataRecieved(object sender, EventArgs e)
            {
                if (_timeoutAfterData)
                {
                    SetTimeout(_lastTimeout, _timeoutAfterData);
                }
            }

            public void Dispose()
            {
                try
                {
                    ((IDisposable)Graph).Dispose();
                }
                catch
                {
                }

                if (Timer != null)
                {
                    try
                    {
                        Timer.Dispose();
                    }
                    catch
                    {
                    }
                }
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="listener"></param>
        /// <param name="factory"></param>
        /// <param name="logger"></param>
        /// <param name="globalMeta"></param>
        /// <param name="proxyServer"></param>
        /// <param name="proxyClient"></param>
        /// <param name="filters"></param>
        /// <param name="defaultTimeout"></param>
        /// <param name="afterdata"></param>
        public ProxyNetworkService(INetworkListener listener, NetGraphFactory factory, Logger logger,
            MetaDictionary globalMeta,
            ProxyServer proxyServer, ProxyClient proxyClient, ProxyFilter[] filters, int defaultTimeout, bool afterdata)
        {
            _packetLog = new List<LogPacket>(1000);
            _logger = logger;
            Listener = listener;

            _factory = factory;
            _connections = new List<ConnectionEntry>();
            _globalMeta = globalMeta;
            _history = new List<ConnectionHistoryEntry>();
            _subServices = new List<ProxyNetworkService>();
            DefaultBinding = NetworkLayerBinding.Default;
            _proxyClient = proxyClient;
            _proxyServer = proxyServer;
            _filters = filters;
            _defaultTimeout = defaultTimeout;
            _afterData = afterdata;
        }

        private ProxyToken FilterToken(ProxyToken token)
        {
            if ((_filters != null) && (_filters.Length > 0))
            {
                foreach (var filter in _filters)
                {
                    if (!filter.Disabled && filter.Match(token))
                    {
                        _logger.LogVerbose(CANAPE.Net.Properties.Resources.ProxyNetworkService_MatchedFilter, filter.ToString());
                        filter.Apply(token, _logger);
                        break;
                    }
                }

                return token;
            }

            return token;
        }

        /// <summary>
        /// Connect client
        /// </summary>
        /// <param name="baseAdapter"></param>
        /// <param name="connProperties"></param>
        /// <returns></returns>
        public NetGraph ConnectClient(IDataAdapter baseAdapter, PropertyBag connProperties)
        {
            IDataAdapter server = null;
            IDataAdapter client = null;
            ProxyToken token = null;
            NetGraph graph = null;
            NetGraph retGraph = null;
            MetaDictionary meta = new MetaDictionary();
            PropertyBag properties = new PropertyBag("Properties");

            try
            {
                properties.AddBag(connProperties);

                token = _proxyServer.Accept(baseAdapter, meta, _globalMeta, this);

                if (token != null)
                {
                    token = FilterToken(token);
                    if (token.Status == NetStatusCodes.Success)
                    {
                        ProxyClient proxyClient = token.Client ?? _proxyClient;

                        if (token.Bind)
                        {
                            client = proxyClient.Bind(token, _logger, meta, _globalMeta, properties.AddBag("Client"));
                        }
                        else
                        {
                            client = proxyClient.Connect(token, _logger, meta, _globalMeta, properties.AddBag("Client"));
                        }

                        server = _proxyServer.Complete(token, meta, _globalMeta, this, client);

                        if ((token.Status == NetStatusCodes.Success) && (client != null))
                        {
                            NetGraphFactory factory = token.Graph != null ? token.Graph : _factory;

                            token.PopulateBag(properties.AddBag("Token"));

                            // Negotiate SSL or other bespoke encryption mechanisms
                            if (token.Layers != null)
                            {
                                foreach (INetworkLayer layer in token.Layers)
                                {
                                    layer.Negotiate(ref server, ref client, token, _logger, meta,
                                        _globalMeta, properties, DefaultBinding);
                                }
                            }

                            var clients = factory.GetNodes<ClientEndpointFactory>();
                            var servers = factory.GetNodes<ServerEndpointFactory>();

                            if ((clients.Length > 0) && (servers.Length > 0))
                            {
                                graph = CreateNetGraph(factory, meta, properties);

                                graph.BindEndpoint(clients[0].Id, client);
                                graph.BindEndpoint(servers[0].Id, server);
                                if (token.NetworkDescription != null)
                                {
                                    graph.NetworkDescription = token.NetworkDescription;
                                }
                                else
                                {
                                    graph.NetworkDescription = String.Format("{0} <=> {1}",
                                        server.Description, client.Description);
                                }

                                PropertyBag networkService = properties.AddBag("NetworkService");

                                networkService.AddValue("ClientId", clients[0].Id);
                                networkService.AddValue("ServerId", servers[0].Id);
                                networkService.AddValue("ClientAdapter", client);
                                networkService.AddValue("ServerAdapter", server);
                                networkService.AddValue("Token", token);

                                graph.Start();

                                OnNewConnection(graph);

                                retGraph = graph;
                            }
                            else
                            {
                                _logger.LogError(CANAPE.Net.Properties.Resources.ProxyNetworkService_InvalidGraph);
                            }
                        }
                    }
                    else
                    {
                        _logger.LogVerbose(CANAPE.Net.Properties.Resources.ProxyNetworkService_ConnectionFiltered);
                        server = _proxyServer.Complete(token, meta, _globalMeta, this, client);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex);
            }
            finally
            {
                if (retGraph == null)
                {
                    try
                    {
                        if (graph != null)
                        {
                            ((IDisposable)graph).Dispose();
                        }
                        if (server != null)
                        {
                            server.Dispose();
                        }
                        if (client != null)
                        {
                            client.Dispose();
                        }
                        if (token != null)
                        {
                            token.Dispose();
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.SystemLogger.LogException(ex);
                    }
                }
            }

            return retGraph;
        }

        /// <summary>
        /// Reconnect a client using TCP
        /// </summary>
        /// <param name="graph">The network graph to reconnect</param>
        /// <param name="hostname">The hostname</param>
        /// <param name="port">The TCP port</param>
        public void ReconnectClientTcp(NetGraph graph, string hostname, int port)
        {
            ReconnectClient(graph, new IpProxyToken(null, hostname, port, IpProxyToken.IpClientType.Tcp, false));
        }

        /// <summary>
        /// Reconnect a client using UDP
        /// </summary>
        /// <param name="graph">The network graph to reconnect</param>
        /// <param name="hostname">The hostname</param>
        /// <param name="port">The UDP port</param>
        public void ReconnectClientUdp(NetGraph graph, string hostname, int port)
        {
            ReconnectClient(graph, new IpProxyToken(null, hostname, port, IpProxyToken.IpClientType.Udp, false));
        }

        // TODO: Should merge with implementation for the general connection so that it is 100% compatible
        /// <summary>
        /// 
        /// </summary>
        /// <param name="graph"></param>
        /// <param name="token"></param>        
        public void ReconnectClient(NetGraph graph, ProxyToken token)
        {
            IDataAdapter client = null;
            bool connected = false;
            PropertyBag networkService = graph.ConnectionProperties.GetRelativeBag("NetworkService");
            PropertyBag clientProperties = graph.ConnectionProperties.GetRelativeBag("Client");
            PropertyBag tokenProperties = graph.ConnectionProperties.GetRelativeBag("Token");

            try
            {
                while (graph.Parent != null)
                {
                    graph = graph.Parent;
                }

                if (token != null)
                {
                    // If passed in a token we need to apply filters to it
                    token = FilterToken(token);
                }
                else
                {
                    // Use original post-filtered
                    token = (ProxyToken)networkService.GetRelativeValue("Token");
                }

                if (token.Status == NetStatusCodes.Success)
                {
                    clientProperties.Clear();

                    if (token.Client == null)
                    {
                        client = _proxyClient.Connect(token, _logger, graph.Meta, _globalMeta, clientProperties);
                    }
                    else
                    {
                        client = token.Client.Connect(token, _logger, graph.Meta, _globalMeta, clientProperties);
                    }

                    tokenProperties.Clear();
                    token.PopulateBag(tokenProperties);

                    // Negotiate SSL or other bespoke encryption mechanisms
                    if (token.Layers != null)
                    {
                        // Bind but disabling server layer
                        NetworkLayerBinding binding = DefaultBinding & ~NetworkLayerBinding.Server;

                        foreach (INetworkLayer layer in token.Layers)
                        {
                            IDataAdapter server = null;

                            layer.Negotiate(ref server, ref client, token, _logger, graph.Meta, _globalMeta, graph.ConnectionProperties, binding);
                        }
                    }

                    graph.BindEndpoint((Guid)networkService.GetRelativeValue("ClientId"), client);

                    IDataAdapter serverAdapter = networkService.GetRelativeValue("ServerAdapter");

                    if (token.NetworkDescription != null)
                    {
                        graph.NetworkDescription = token.NetworkDescription;
                    }
                    else
                    {
                        graph.NetworkDescription = String.Format("{0} <=> {1}",
                            serverAdapter.Description, client.Description);
                    }

                    IDataAdapter oldClient = networkService.GetRelativeValue("ClientAdapter");

                    networkService.AddValue("ClientAdapter", client);
                    networkService.AddValue("Token", token);

                    oldClient.Dispose();

                    connected = true;
                }
                else
                {
                    _logger.LogVerbose(Properties.Resources.ProxyNetworkService_ConnectionFiltered);
                }
            }
            catch (Exception ex)
            {
                _logger.LogException(ex);
            }
            finally
            {
                if (!connected)
                {
                    try
                    {
                        if (client != null)
                        {
                            client.Dispose();
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.SystemLogger.LogException(ex);
                    }
                }
            }
        }

        /// <summary>
        /// Method called when a new client connects
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnClientConnected(object sender, ClientConnectedEventArgs e)
        {
            NetGraph graph = ConnectClient(e.DataAdapter, e.Properties);

            if (graph == null)
            {
                e.DataAdapter.Dispose();
            }
        }

        /// <summary>
        /// Create the netgraph for a connection
        /// </summary>
        /// <param name="factory">The netgraph factory</param>
        /// <param name="meta">Current meta data</param>
        /// <param name="properties">Property bag</param>
        /// <returns>The created graph</returns>
        private NetGraph CreateNetGraph(NetGraphFactory factory, MetaDictionary meta, PropertyBag properties)
        {
            NetGraph g = factory == null ? _factory.Create(_logger, null, _globalMeta, meta, properties) : factory.Create(_logger, null, _globalMeta, meta, properties);
            if (g != null)
            {
                g.LogPacketEvent += new EventHandler<LogPacketEventArgs>(log_AddLogPacket);
                g.EditPacketEvent += new EventHandler<EditPacketEventArgs>(edit_InputReceived);
                g.GraphShutdown += new EventHandler(graph_GraphShutdown);
            }

            return g;
        }

        private void log_AddLogPacket(object sender, LogPacketEventArgs e)
        {
            LogPacket packet = new LogPacket(e);

            if (LogPacketEvent != null)
            {
                PacketLogEventArgs args = new PacketLogEventArgs(packet, sender as NetGraph);

                LogPacketEvent.Invoke(this, args);

                if (args.Filter)
                {
                    packet = null;
                }
                else
                {
                    packet = args.Packet;
                }
            }

            if (packet != null)
            {
                lock (_packetLog)
                {
                    _packetLog.Add(packet);
                }
            }
        }

        private void edit_InputReceived(object sender, EditPacketEventArgs e)
        {
            if (EditPacketEvent != null)
            {
                EditPacketEvent.Invoke(sender, e);
            }
        }

        /// <summary>
        /// Method called for a new connection
        /// </summary>
        /// <param name="graph">The new connection graph</param>
        private void OnNewConnection(NetGraph graph)
        {
            bool connAdded = false;

            lock (_connections)
            {
                if (_state == (int)ServiceState.Running)
                {
                    _connections.Add(new ConnectionEntry(this, graph, _defaultTimeout, _afterData));
                    connAdded = true;
                }
            }

            if (connAdded)
            {
                NewConnectionEvent?.Invoke(this, new ConnectionEventArgs(graph));

                if (_logger != null)
                {
                    _logger.LogVerbose(CANAPE.Net.Properties.Resources.NetworkServiceBase_ConnectionEstablished,
                        graph.NetworkDescription);
                }
            }
            else
            {
                // We are not running don't add it, just kill
                try
                {
                    ((IDisposable)graph).Dispose();
                }
                catch
                {
                }
            }
        }

        private void graph_GraphShutdown(object sender, EventArgs e)
        {
            CloseConnection(sender as NetGraph);
        }

        /// <summary>
        /// Start the network service
        /// </summary>
        public void Start()
        {
            if (Interlocked.CompareExchange(ref _state,
                (int)ServiceState.RunPending, (int)ServiceState.Stopped) ==
                (int)ServiceState.Stopped)
            {
                try
                {
                    _listener.Start();
                    _state = (int)ServiceState.Running;
                }
                catch (Exception ex)
                {
                    _state = (int)ServiceState.Stopped;
                    throw new NetServiceException(CANAPE.Net.Properties.Resources.NetworkServiceBase_CouldNotStartService, ex);
                }
            }
        }

        /// <summary>
        /// Stop the service immediately
        /// </summary>
        public void Stop()
        {
            Stop(0);
        }

        /// <summary>
        /// Stop the service, waiting for a period of time for before shutdown
        /// </summary>
        /// <param name="timeout">The number of milliseconds to wait, 0 for immediate shutdown, &lt; 0 for infinite wait</param>
        public void Stop(int timeout)
        {
            if ((Interlocked.CompareExchange(ref _state,
                (int)ServiceState.StopPending, (int)ServiceState.Running) ==
                (int)ServiceState.Running))
            {
                try
                {
                    NewConnectionEvent = null;

                    lock (_subServices)
                    {
                        foreach (ProxyNetworkService subService in _subServices)
                        {
                            subService.Stop(timeout);
                        }
                    }

                    _listener.Stop();

                    // Only stop connections at the root
                    if (_parentService == null)
                    {
                        ConnectionEntry[] graphs;

                        lock (_connections)
                        {
                            graphs = _connections.ToArray();
                        }

                        if (graphs.Length > 0)
                        {
                            foreach (ConnectionEntry g in graphs)
                            {
                                if (timeout == 0)
                                {
                                    CloseConnection(g);
                                }
                                else
                                {
                                    g.SetTimeout(timeout, false);
                                }
                            }
                        }
                        else
                        {
                            CompleteStop();
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogException(ex);
                }
            }
            else if ((timeout == 0) && (_state == (int)ServiceState.StopPending) && (_parentService == null))
            {
                ConnectionEntry[] graphs;

                lock (_connections)
                {
                    graphs = _connections.ToArray();
                }

                foreach (ConnectionEntry g in graphs)
                {
                    CloseConnection(g);
                }
            }
        }

        private void CompleteStop()
        {
            try
            {
                LogPacketEvent = null;
                EditPacketEvent = null;

                lock (_subServices)
                {
                    foreach (ProxyNetworkService subService in _subServices)
                    {
                        subService.CompleteStop();
                    }
                    _subServices.Clear();
                }

                CloseConnectionEvent = null;
            }
            catch (Exception ex)
            {
                _logger.LogException(ex);
            }
            finally
            {
                _state = (int)ServiceState.Stopped;
                ServiceStoppedEvent?.Invoke(this, new EventArgs());
                ServiceStoppedEvent = null;
            }
        }

        /// <summary>
        /// Indicates the service is active
        /// </summary>
        public bool Active
        {
            get { return _state == (int)ServiceState.Running; }
        }

        /// <summary>
        /// Get list of open connections
        /// </summary>
        public NetGraph[] Connections
        {
            get
            {
                lock (_connections)
                {
                    return _connections.Select(f => f.Graph).ToArray();
                }
            }
        }

        /// <summary>
        /// Get or set the listener object for this service
        /// </summary>
        public INetworkListener Listener
        {
            get
            {
                return _listener;
            }

            set
            {
                if (_listener != value)
                {
                    if (_listener != null)
                    {
                        _listener.ClientConnected -= OnClientConnected;
                    }
                    _listener = value;
                    _listener.ClientConnected += OnClientConnected;
                }
            }
        }

        private void CloseConnection(ConnectionEntry entry)
        {
            NetGraph graph = entry.Graph;

            lock (entry)
            {
                if (!graph.IsDisposed)
                {
                    ConnectionHistoryEntry history = new ConnectionHistoryEntry(graph.NetworkDescription, graph.Uuid, graph.Created, DateTime.Now);
                    bool noConnections = false;

                    foreach (KeyValuePair<string, object> pair in graph.ConnectionProperties)
                    {
                        history.Properties[pair.Key] = pair.Value;
                    }

                    try
                    {
                        entry.Dispose();
                    }
                    catch
                    {
                        // Shouldn't throw but just in case
                    }

                    lock (_history)
                    {
                        _history.Add(history);
                    }

                    lock (_connections)
                    {
                        _connections.Remove(entry);
                        if (_connections.Count == 0)
                        {
                            noConnections = true;
                        }
                    }

                    CloseConnectionEvent?.Invoke(this, new ConnectionEventArgs(graph));

                    if (_logger != null)
                    {
                        _logger.LogVerbose(CANAPE.Net.Properties.Resources.NetworkServiceBase_ConnectionClosed, graph.NetworkDescription);
                    }

                    if ((_state == (int)ServiceState.StopPending) && noConnections)
                    {
                        CompleteStop();
                    }
                }
            }
        }

        private ConnectionEntry GetConnection(NetGraph graph)
        {
            // Ensure at parent graph
            while (graph.Parent != null)
            {
                graph = graph.Parent;
            }

            lock (_connections)
            {
                for (int i = 0; i < _connections.Count; ++i)
                {
                    if (_connections[i].Graph == graph)
                    {
                        return _connections[i];
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Close a connection
        /// </summary>
        /// <param name="graph">The graph to close</param>
        public void CloseConnection(NetGraph graph)
        {
            ConnectionEntry entry = GetConnection(graph);

            if (entry != null)
            {
                CloseConnection(entry);
            }
        }

        private void ConnectionTimeout(object state)
        {
            CloseConnection((ConnectionEntry)state);
        }

        /// <summary>
        /// Set a timeout on a connection
        /// </summary>
        /// <param name="graph">The graph to set the timeout on</param>
        /// <param name="timeout">The timeout value in milliseconds</param>
        /// <param name="afterdata">True to timeout after last data received, otherwise absolute</param>
        public void SetTimeout(NetGraph graph, int timeout, bool afterdata)
        {
            ConnectionEntry entry = GetConnection(graph);

            if (entry != null)
            {
                lock (entry)
                {
                    entry.SetTimeout(timeout, afterdata);
                }
            }
        }

        /// <summary>
        /// Event for when a new connection is created
        /// </summary>
        public event EventHandler<ConnectionEventArgs> NewConnectionEvent;

        /// <summary>
        /// Event for when a packet is logged, this allows something to filter out or capture packets before
        /// being logged to the service
        /// </summary>
        public event EventHandler<PacketLogEventArgs> LogPacketEvent;

        /// <summary>
        /// Event for when a packet needs to be edited
        /// </summary>
        public event EventHandler<EditPacketEventArgs> EditPacketEvent;

        /// <summary>
        /// Event for a when a connection is closed
        /// </summary>
        public event EventHandler<ConnectionEventArgs> CloseConnectionEvent;

        /// <summary>
        /// Event called if the service is stopped
        /// </summary>
        public event EventHandler ServiceStoppedEvent;

        /// <summary>
        /// Indicates the default binding mode for the service
        /// </summary>
        public NetworkLayerBinding DefaultBinding { get; set; }
        
        /// <summary>
        /// Get connection history for this service.
        /// </summary>
        public IEnumerable<ConnectionHistoryEntry> ConnectionHistory
        {
            get
            {
                lock (_history)
                {
                    return _history.ToArray();
                }
            }
        }

        /// <summary>
        /// Get log of packets captured by this service.
        /// </summary>
        public LogPacketCollection Packets
        {
            get
            {
                lock (_packetLog)
                {
                    return new LogPacketCollection(_packetLog);
                }
            }
        }

        /// <summary>
        /// Helper method to get the layer binding from the graph
        /// </summary>
        /// <param name="graph">The graph</param>
        /// <returns>The network layer binding, if no service returns default</returns>
        public static NetworkLayerBinding GetLayerBinding(NetGraph graph)
        {
            ProxyNetworkService service = graph.ServiceProvider.GetService<ProxyNetworkService>();

            if (service != null)
            {
                return service.DefaultBinding;
            }
            else
            {
                return NetworkLayerBinding.Default;
            }
        }

        /// <summary>
        /// Add a sub service to the service. This will start the service
        /// </summary>
        /// <param name="service">The service to add, should not be started</param>
        /// <remarks>This method takes possession of the service</remarks>
        public void AddSubService(ProxyNetworkService service)
        {
            service._connections = _connections;
            service._globalMeta = _globalMeta;
            service._history = _history;
            service._logger = _logger;
            service._connections = _connections;
            service._packetLog = _packetLog;
            service._parentService = this;

            service.CloseConnectionEvent += service_CloseConnectionEvent;
            service.EditPacketEvent += service_EditPacketEvent;
            service.LogPacketEvent += service_FilterLogPacketEvent;
            service.NewConnectionEvent += service_NewConnectionEvent;
            service.ServiceStoppedEvent += service_ServiceStoppedEvent;

            service.Start();
        }

        /// <summary>
        /// Remove an existing sub service
        /// </summary>
        /// <param name="service">The sub service to remove</param>
        public void RemoveSubService(ProxyNetworkService service)
        {
            service.Stop();
        }

        private void service_ServiceStoppedEvent(object sender, EventArgs e)
        {
            ProxyNetworkService service = sender as ProxyNetworkService;

            lock (_subServices)
            {
                _subServices.Remove(service);
            }
        }

        private void service_NewConnectionEvent(object sender, ConnectionEventArgs e)
        {
            NewConnectionEvent?.Invoke(sender, e);
        }

        private void service_FilterLogPacketEvent(object sender, PacketLogEventArgs e)
        {
            LogPacketEvent?.Invoke(sender, e);
        }

        private void service_EditPacketEvent(object sender, EditPacketEventArgs e)
        {
            EditPacketEvent?.Invoke(sender, e);
        }

        private void service_CloseConnectionEvent(object sender, ConnectionEventArgs e)
        {
            CloseConnectionEvent?.Invoke(sender, e);
        }
    }
}
