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
using CANAPE.DataFrames;
using CANAPE.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace CANAPE.Nodes
{
    /// <summary>
    /// Netgraph object
    /// </summary>
    public sealed class NetGraph : IDisposable
    {
        /// <summary>
        /// Value to indicate the graph has already been disposed
        /// </summary>
        private bool _isDisposed;

        /// <summary>
        /// Value to indicate the graph has been shutdown
        /// </summary>
        private int _graphShutdown;

        /// <summary>
        /// The list of nodes in the graph
        /// </summary>
        public Dictionary<Guid, BasePipelineNode> Nodes { get; private set; }

        /// <summary>
        /// Global meta data (global to the current service)
        /// </summary>
        public MetaDictionary GlobalMeta { get; private set; }

        /// <summary>
        /// Extra meta-data associated with the graph
        /// </summary>
        public MetaDictionary Meta { get; private set; }

        /// <summary>
        /// List of user defined properties
        /// </summary>
        public ConcurrentDictionary<string, string> Properties { get; private set; }

        /// <summary>
        /// A container for read only properties about the connection
        /// </summary>
        public PropertyBag ConnectionProperties { get; private set; }

        /// <summary>
        /// A unique random guid generated for each new graph
        /// </summary>
        public Guid Uuid { get; private set; }

        /// <summary>
        /// Textual description of the network
        /// </summary>
        public string NetworkDescription { get; set; }

        /// <summary>
        /// Get or set the logger
        /// </summary>
        public Logger Logger { get; private set; }

        /// <summary>
        /// Indicates the parent graph, set to null if no parent
        /// </summary>
        public NetGraph Parent { get; private set; }

        /// <summary>
        /// Provides a name for the graph
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Indicates the number of ticks when this graph was created
        /// </summary>
        public TimeSpan CreatedTicks { get; private set; }

        /// <summary>
        /// Indicates the original time when this was created.
        /// </summary>
        public DateTime Created { get; private set; }

        /// <summary>
        /// An ServiceProvider for services related to this connection
        /// </summary>
        public ServiceProvider ServiceProvider { get; private set; }

        /// <summary>
        /// An event which indicates the graph has been shutdown
        /// </summary>
        public event EventHandler GraphShutdown;

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="globalMeta">Global meta data</param>
        /// <param name="logger">Logger</param>
        /// <param name="meta">Local meta data</param>
        /// <param name="parent">Parent graph if available</param>
        /// <param name="properties">A property bag associated with this connection</param>
        public NetGraph(Logger logger, NetGraph parent, MetaDictionary globalMeta, MetaDictionary meta, PropertyBag properties)
        {
            Nodes = new Dictionary<Guid, BasePipelineNode>();
            if (meta == null)
            {
                Meta = new MetaDictionary();
            }
            else
            {
                Meta = meta;
            }

            Properties = new ConcurrentDictionary<string, string>();
            ConnectionProperties = properties;
            GlobalMeta = globalMeta;
            Uuid = Guid.NewGuid();
            if (logger != null)
            {
                Logger = logger;
            }
            else
            {
                Logger = Logger.SystemLogger;
            }
            NetworkDescription = "Unknown";
            Name = String.Empty;
            Parent = parent;
            Created = DateTime.Now;
            CreatedTicks = new TimeSpan(DateTime.UtcNow.Ticks);

            if (parent == null)
            {
                ServiceProvider = new ServiceProvider();
            }
            else
            {
                ServiceProvider = parent.ServiceProvider;
            }
        }

        #region Meta Data Handling

        /// <summary>
        /// Get a meta value from the public scope
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>         
        /// <returns>The dynamic object or null if not found</returns>        
        public dynamic GetMeta(string name)
        {
            return Meta.GetMeta(name);
        }

        /// <summary>
        /// Get a meta value from the public scope, if it does not exist then add to the meta
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>     
        /// <param name="defaultValue">The default value to add, if null no value will be added</param>
        /// <returns>The dynamic object the default value if it does not exist</returns>   
        public dynamic GetMeta(string name, dynamic defaultValue)
        {
            return Meta.GetMeta(name, defaultValue);
        }

        /// <summary>
        /// Get a meta value, if it does not exist then add to the meta
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>         
        /// <param name="defaultValue">The default value to add, if null no value will be added</param>
        /// <param name="privateScope">If true then searches the private scope</param>
        /// <returns>The dynamic object the default value if it does not exist</returns>  
        public dynamic GetMeta(string name, dynamic defaultValue, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;

            return Meta.GetMeta(fullName, defaultValue);
        }

        /// <summary>
        /// Set a meta value
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>
        /// <param name="obj">The dynamic object, set to null to remove</param>
        /// <param name="privateScope">If true then added to private meta scope</param>
        public void SetMeta(string name, dynamic obj, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;

            Meta.SetMeta(fullName, obj);
        }

        /// <summary>
        /// Set a meta value, in the public scope 
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>
        /// <param name="obj">The dynamic object, set to null to remove</param>        
        public void SetMeta(string name, dynamic obj)
        {
            Meta.SetMeta(name, obj);
        }

        /// <summary>
        /// Get a global meta value from the public scope
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>         
        /// <returns>The dynamic object or null if not found</returns>        
        public dynamic GetGlobalMeta(string name)
        {
            return GlobalMeta.GetMeta(name);
        }

        /// <summary>
        /// Get a global meta value from the public scope, if it does not exist then add to the meta
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>     
        /// <param name="defaultValue">The default value to add, if null no value will be added</param>
        /// <returns>The dynamic object the default value if it does not exist</returns>   
        public dynamic GetGlobalMeta(string name, dynamic defaultValue)
        {
            return GlobalMeta.GetMeta(name, defaultValue);
        }

        /// <summary>
        /// Get a global meta value, if it does not exist then add to the meta
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>         
        /// <param name="defaultValue">The default value to add, if null no value will be added</param>
        /// <param name="privateScope">If true then searches the private scope</param>
        /// <returns>The dynamic object the default value if it does not exist</returns>  
        public dynamic GetGlobalMeta(string name, dynamic defaultValue, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;

            return GlobalMeta.GetMeta(fullName, defaultValue);
        }

        /// <summary>
        /// Set a global meta value
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>
        /// <param name="obj">The dynamic object, set to null to remove</param>
        /// <param name="privateScope">If true then added to private meta scope</param>
        public void SetGlobalMeta(string name, dynamic obj, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;

            GlobalMeta.SetMeta(fullName, obj);
        }

        /// <summary>
        /// Set a global meta value, in the public scope 
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>
        /// <param name="obj">The dynamic object, set to null to remove</param>        
        public void SetGlobalMeta(string name, dynamic obj)
        {
            GlobalMeta.SetMeta(name, obj);
        }

        /// <summary>
        /// Get a counter from the meta
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="defaultValue">The default value if it doesn't exist</param>
        /// <param name="privateScope">Whether to add in private scope</param>
        /// <returns>The current value of the counter</returns>
        public int GetCounter(string name, int defaultValue, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;

            return Meta.GetCounter(fullName, defaultValue);
        }

        /// <summary>
        /// Get a counter from the meta public scope
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="defaultValue">The default value if it doesn't exist</param>
        /// <returns>The current value of the counter</returns>
        public int GetCounter(string name, int defaultValue)
        {
            return Meta.GetCounter(name, defaultValue);
        }

        /// <summary>
        /// Increment a counter, will add if it doesn't exist (starting from 0)
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="increment">The value to increment the counter by</param>
        /// <param name="privateScope">Whether to add in private scope</param>
        /// <returns>The new value of the counter</returns>
        public int IncrementCounter(string name, int increment, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;

            return Meta.IncrementCounter(fullName, increment);
        }

        /// <summary>
        /// Increment a counter in the public scope, will add if it doesn't exist (starting from 0)
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="increment">The value to increment the counter by</param>
        /// <returns>The new value of the counter</returns>
        public int IncrementCounter(string name, int increment)
        {
            return Meta.IncrementCounter(name, increment);
        }

        /// <summary>
        /// Set a counter to a specific value
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="value">The value of the counter</param>
        /// <param name="privateScope">Whether to add in private scope</param>
        public void SetCounter(string name, int value, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;

            Meta.SetCounter(fullName, value);
        }

        /// <summary>
        /// Set a counter to a specific value
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="value">The value of the counter</param>        
        public void SetCounter(string name, int value)
        {
            Meta.SetCounter(name, value);
        }

        /// <summary>
        /// Get a counter from the global meta
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="defaultValue">The default value if it doesn't exist</param>
        /// <param name="privateScope">Whether to add in private scope</param>
        /// <returns>The current value of the counter</returns>
        public int GetGlobalCounter(string name, int defaultValue, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;

            return GlobalMeta.GetCounter(fullName, defaultValue);
        }

        /// <summary>
        /// Get a counter from the global meta public scope
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="defaultValue">The default value if it doesn't exist</param>
        /// <returns>The current value of the counter</returns>
        public int GetGlobalCounter(string name, int defaultValue)
        {
            return GlobalMeta.GetCounter(name, defaultValue);
        }

        /// <summary>
        /// Increment a global counter, will add if it doesn't exist (starting from 0)
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="increment">The value to increment the counter by</param>
        /// <param name="privateScope">Whether to add in private scope</param>
        /// <returns>The new value of the counter</returns>
        public int IncrementGlobalCounter(string name, int increment, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;
            return GlobalMeta.IncrementCounter(fullName, increment);
        }

        /// <summary>
        /// Increment a global counter in the public scope, will add if it doesn't exist (starting from 0)
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="increment">The value to increment the counter by</param>        
        /// <returns>The new value of the counter</returns>
        public int IncrementGlobalCounter(string name, int increment)
        {
            return GlobalMeta.IncrementCounter(name, increment);
        }

        /// <summary>
        /// Set a global counter to a specific value
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="value">The value of the counter</param>
        /// <param name="privateScope">Whether to add in private scope</param>
        public void SetGlobalCounter(string name, int value, bool privateScope)
        {
            string fullName = privateScope ? GeneralUtils.MakePrivateMetaName(Uuid, name) : name;
            GlobalMeta.SetCounter(fullName, value);
        }

        /// <summary>
        /// Set a global counter to a specific value
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="value">The value of the counter</param>        
        public void SetGlobalCounter(string name, int value)
        {
            GlobalMeta.SetCounter(name, value);
        }

        /// <summary>
        /// Get a property value
        /// </summary>
        /// <param name="name">The name of the property</param>
        /// <returns>The property string, null if not available</returns>
        public string GetProperty(string name)
        {
            string ret = null;

            if (Properties != null)
            {
                if (!Properties.TryGetValue(name, out ret))
                {
                    ret = null;
                }
            }

            return ret;
        }

        /// <summary>
        /// Set a property value
        /// </summary>
        /// <param name="name">The name</param>
        /// <param name="value">The value, null to remove it</param>
        public void SetProperty(string name, string value)
        {
            if (Properties != null)
            {
                Properties[name] = value;
            }
            else
            {
                if (Properties.ContainsKey(name))
                {
                    string val;
                    Properties.TryRemove(name, out val);
                }
            }
        }

        #endregion

        /// <summary>
        /// Get a node by name
        /// </summary>
        /// <param name="name">The name of the node or the UUID</param>
        /// <returns>The node instance, or null if it doesn't exist</returns>
        public BasePipelineNode GetNodeByName(string name)
        {
            Guid guid;

            if (!Guid.TryParse(name, out guid) || Nodes.ContainsKey(guid))
            {
                foreach (BasePipelineNode node in Nodes.Values)
                {
                    if (node.Name.Equals(name, StringComparison.CurrentCultureIgnoreCase))
                    {
                        return node;
                    }
                }

                return null;
            }
            else
            {
                return Nodes[guid];
            }
        }

        /// <summary>
        /// Add a node to the graph and ensure shutdown event is handled
        /// </summary>
        /// <param name="uuid">The Guid of the factory</param>
        /// <param name="node">The node itself</param>
        public void AddNode(Guid uuid, BasePipelineNode node)
        {
            Nodes.Add(uuid, node);

            node.NodeShutdown += new EventHandler(node_NodeShutdown);
        }

        private void DoGraphShutdown()
        {
            int graphShutdown = Interlocked.Exchange(ref _graphShutdown, 1);

            if (graphShutdown == 0)
            {
                if (GraphShutdown != null)
                {
                    GraphShutdown(this, new EventArgs());
                }
            }
        }

        private void node_NodeShutdown(object sender, EventArgs e)
        {
            if (CheckShutdown())
            {
                DoGraphShutdown();
            }
        }

        /// <summary>
        /// Indicates the connection is disposed
        /// </summary>
        public bool IsDisposed
        {
            get
            {
                return _isDisposed;
            }
        }

        /// <summary>
        /// Check if shutdown, all nodes with an inbound connection must be shutdown
        /// </summary>
        public bool CheckShutdown()
        {
            bool ret = true;

            if (!_isDisposed && _graphShutdown == 0)
            {
                HashSet<Guid> referencedNodes = new HashSet<Guid>();

                foreach (KeyValuePair<Guid, BasePipelineNode> pair in Nodes)
                {
                    foreach (BasePipelineNode node in pair.Value.Outputs)
                    {
                        if (!referencedNodes.Contains(node.Uuid))
                        {
                            referencedNodes.Add(node.Uuid);
                        }
                    }
                }

                foreach (KeyValuePair<Guid, BasePipelineNode> pair in Nodes)
                {
                    if (!pair.Value.IsShutdown && referencedNodes.Contains(pair.Value.Uuid))
                    {
                        ret = false;
                        break;
                    }
                }
            }

            return ret;
        }

        /// <summary>
        /// Method to bind an endpoint
        /// </summary>
        /// <param name="id"></param>
        /// <param name="adapter"></param>
        public void BindEndpoint(Guid id, IDataAdapter adapter)
        {
            if (Nodes.ContainsKey(id) && (Nodes[id] is IPipelineEndpoint))
            {
                IPipelineEndpoint ep = Nodes[id] as IPipelineEndpoint;

                ep.Adapter = adapter;
            }
            else
            {
                throw new ArgumentException(String.Format(CANAPE.Properties.Resources.NetGraph_InvalidEndpointId, id));
            }
        }

        /// <summary>
        /// Event when the graph wants to log a packet
        /// </summary>
        public event EventHandler<LogPacketEventArgs> LogPacketEvent;

        /// <summary>
        /// Event when the graph wants to edit a packet
        /// </summary>
        public event EventHandler<EditPacketEventArgs> EditPacketEvent;

        /// <summary>
        /// Get the top graph on the stack of parents
        /// </summary>
        /// <returns>The top graph</returns>
        public NetGraph GetTopGraph()
        {
            // Walk to parent 
            NetGraph top = this;
            while (top.Parent != null)
            {
                top = top.Parent;
            }

            return top;
        }

        /// <summary>
        /// Log a packet from the graph
        /// </summary>
        /// <param name="tag">A textual tag for the frame</param>
        /// <param name="color">The color to display the frame (if applicable)</param>
        /// <param name="frame">The frame to log, note this must be cloned to preserve its value</param>
        /// <param name="logAsBytes">Indicates whether the packet should be logged as a byte array</param>
        public void DoLogPacket(string tag, ColorValue color, DataFrame frame, bool logAsBytes)
        {
            GetTopGraph().OnLogPacket(tag, color, frame, logAsBytes);
        }

        /// <summary>
        /// Log a packet from the graph with separated colour values
        /// </summary>
        /// <param name="tag">A textual tag for the frame</param>
        /// <param name="r">Red value</param>
        /// <param name="g">Green value</param>
        /// <param name="b">Blue value</param>
        /// <param name="frame">The frame to log, note this will be cloned to preserve its value</param>
        /// <param name="logAsBytes">Indicates whether the packet should be logged as a byte array</param>
        public void DoLogPacket(string tag, byte r, byte g, byte b, DataFrame frame, bool logAsBytes)
        {
            DoLogPacket(tag, new ColorValue(r, g, b), frame, logAsBytes);
        }

        /// <summary>
        /// Log a packet from the graph
        /// </summary>
        /// <param name="tag">A textual tag for the frame</param>
        /// <param name="color">The color to display the frame (if applicable)</param>
        /// <param name="frame">The frame to log, note this must be cloned to preserve its value</param>
        /// <param name="logAsBytes">Indicates whether the packet should be logged as a byte array</param>
        private void OnLogPacket(string tag, ColorValue color, DataFrame frame, bool logAsBytes)
        {
            EventHandler<LogPacketEventArgs> logPacketEvent = LogPacketEvent;

            if (logPacketEvent != null)
            {
                DataFrame logFrame = logAsBytes ? new ByteArrayDataFrame(frame.ToArray())
                    : frame.Clone();

                logPacketEvent(this, new LogPacketEventArgs(tag, Uuid,
                                                            logFrame,
                                                            color,
                                                            NetworkDescription));
            }
        }

        /// <summary>
        /// Method to dispatch edit packet event
        /// </summary>
        /// <param name="graph">The graph which originated the edit</param>
        /// <param name="e">The event arguments</param>
        /// <returns></returns>
        private void OnEditPacket(NetGraph graph, EditPacketEventArgs e)
        {
            EventHandler<EditPacketEventArgs> editPacketEvent = EditPacketEvent;

            if (editPacketEvent != null)
            {
                editPacketEvent(graph, e);
            }
        }

        /// <summary>
        /// Edit a packet from the graph
        /// </summary>
        /// <param name="frame">The frame to edit</param>
        /// <param name="sender">The sending nod</param>
        /// <param name="color">The colour to show in an edit window (if applicable)</param>
        /// <param name="tag">The textual tag to show in an edit window (if applicable)</param>
        /// <returns>The returned frame, this may or may not be the same frame as sent</returns>        
        public DataFrame DoEditPacket(DataFrame frame, BasePipelineNode sender, ColorValue color, string tag)
        {
            NetGraph top = GetTopGraph();

            EditPacketEventArgs args = new EditPacketEventArgs(frame, sender, color, tag);

            top.OnEditPacket(this, args);

            return args.Frame;
        }

        /// <summary>
        /// Start the netgraph running
        /// </summary>
        public void Start()
        {
            foreach (var pair in Nodes)
            {
                try
                {
                    if (pair.Value is IPipelineEndpoint)
                    {
                        ((IPipelineEndpoint)pair.Value).Start();
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogException(ex);
                }
            }
        }

        /// <summary>
        /// To string override
        /// </summary>
        /// <returns>The name of the graph</returns>
        public override string ToString()
        {
            return Name;
        }

        #region IDisposable Members

        void IDisposable.Dispose()
        {
            if (!_isDisposed)
            {
                try
                {
                    GC.SuppressFinalize(this);

                    _isDisposed = true;
                    LogPacketEvent = null;
                    EditPacketEvent = null;
                    foreach (var pair in Nodes)
                    {
                        try
                        {
                            IDisposable d = pair.Value as IDisposable;
                            if (d != null)
                            {
                                d.Dispose();
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.SystemLogger.LogException(ex);
                        }
                    }

                    // Only dispose the meta data if this is the top level graph _or_ our meta doesn't equal our parents
                    if ((Parent == null) || (Parent.Meta != Meta))
                    {
                        foreach (dynamic value in Meta.Values)
                        {
                            try
                            {
                                IDisposable d = value as IDisposable;

                                if (d != null)
                                {
                                    d.Dispose();
                                }
                            }
                            catch (Exception ex)
                            {
                                Logger.SystemLogger.LogException(ex);
                            }
                        }

                        Meta.Clear();
                    }

                    // Only dispose the connection properties if this is the top level graph
                    if (Parent == null)
                    {
                        ((IDisposable)ConnectionProperties).Dispose();
                        ConnectionProperties.Clear();
                    }
                }
                finally
                {
                    DoGraphShutdown();
                }
            }
        }

        #endregion
    }
}
