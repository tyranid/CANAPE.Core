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
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Collections.Generic;

namespace CANAPE.NodeFactories
{
    /// <summary>
    /// Factory object for a net graph
    /// </summary>    
    public sealed class NetGraphFactory
    {
        private object _lockObject = new object();

        /// <summary>
        /// Entry for a graphnode
        /// </summary>        
        public sealed class GraphNodeEntry
        {
            /// <summary>
            /// Id of the node (calls down to the factory)
            /// </summary>
            public Guid Id
            {
                get
                {
                    return Factory.Id;
                }
            }

            /// <summary>
            /// The node factory object
            /// </summary>
            public BaseNodeFactory Factory { get; set; }

            /// <summary>
            /// Overridden form of ToString
            /// </summary>
            /// <returns>The label of the node</returns>
            public override string ToString()
            {
                return Factory.ToString();
            }

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="factory">The node factory</param>
            public GraphNodeEntry(BaseNodeFactory factory)
            {
                Factory = factory;
            }

            /// <summary>
            /// Default constructor
            /// </summary>
            public GraphNodeEntry() : this(null)
            {
            }
        }

        /// <summary>
        /// Entry for a graph line
        /// </summary>        
        public sealed class GraphLineEntry
        {
            /// <summary>
            /// The source node to which this attaches
            /// </summary>
            public Guid SourceNode { get; set; }

            /// <summary>
            /// The destination node to which this attaches
            /// </summary>
            public Guid DestNode { get; set; }

            /// <summary>
            /// Whether the line is bidirectional
            /// </summary>
            public bool BiDirection { get; set; }

            /// <summary>
            /// The path name
            /// </summary>
            public string PathName { get; set; }

            /// <summary>
            /// Indicates this is a weak path, which means it doesn't contribute
            /// to the shutdown of a node
            /// </summary>
            public bool WeakPath { get; set; }

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="sourceNode">The source node</param>
            /// <param name="destNode">The desintation node</param>
            /// <param name="biDirection">Whether the path is bi-directional</param>
            /// <param name="pathName">The name of the path</param>
            /// <param name="weak">Indicates this is a weak path, which means it doesn't contribute to the shutdown of a node</param>
            public GraphLineEntry(Guid sourceNode, Guid destNode, bool biDirection, string pathName, bool weak)
            {
                SourceNode = sourceNode;
                DestNode = destNode;
                BiDirection = biDirection;
                PathName = pathName;
                WeakPath = weak;
            }
        }

        private Dictionary<string, string> _props;
        private GraphNodeEntry[] _nodes;
        private GraphLineEntry[] _lines;

        /// <summary>
        /// Default constructor
        /// </summary>        
        public NetGraphFactory()
        {
            _props = new Dictionary<string, string>();
            _nodes = new GraphNodeEntry[0];
            _lines = new GraphLineEntry[0];
            Uuid = Guid.NewGuid();
            Name = String.Empty;
        }

        private static NetGraph CreateGraph(string name, Logger logger, NetGraph parent, MetaDictionary globalMeta, MetaDictionary meta,
            IEnumerable<GraphNodeEntry> nodes, IEnumerable<GraphLineEntry> lines, Dictionary<string, string> props, PropertyBag connectionProperties,
            Dictionary<string, object> stateDictionary)
        {
            NetGraph netGraph = new NetGraph(logger, parent, globalMeta, meta, connectionProperties);
            HashSet<Guid> referencedNodes = new HashSet<Guid>();
            netGraph.Name = name != null ? name : String.Empty;

            foreach (GraphNodeEntry n in nodes)
            {
                BasePipelineNode pipeNode = n.Factory.Create(logger, netGraph, stateDictionary);
                if (pipeNode == null)
                {
                    throw new InvalidOperationException("One of the nodes failed to create");
                }

                pipeNode.Graph = netGraph;
                pipeNode.Name = n.Factory.Label;
                pipeNode.Uuid = n.Id;
                netGraph.AddNode(n.Factory.Id, pipeNode);
            }

            foreach (GraphLineEntry l in lines)
            {
                netGraph.Nodes[l.SourceNode].AddOutput(netGraph.Nodes[l.DestNode], l.PathName, l.WeakPath);
                referencedNodes.Add(l.DestNode);

                if (l.BiDirection)
                {
                    netGraph.Nodes[l.DestNode].AddOutput(netGraph.Nodes[l.SourceNode], l.PathName, l.WeakPath);
                }
            }

            foreach (KeyValuePair<string, string> pair in props)
            {
                netGraph.Meta[pair.Key] = pair.Value;
            }

            foreach (Guid uuid in referencedNodes)
            {
                BasePipelineNode node = netGraph.Nodes[uuid];

                node.SetupShutdownOutputs();
            }

            return netGraph;
        }

        /// <summary>
        /// Create a filtered netgraph based on a specific direction
        /// </summary>
        /// <param name="name">The name of the graph</param>
        /// <param name="logger">A logger object</param>
        /// <param name="parent">The parent graph, null if not available</param>
        /// <param name="globalMeta">Global meta dictionary</param>
        /// <param name="meta">Local meta dictionary</param>
        /// <param name="rootNode">The base node for traversing the graph</param>
        /// <param name="connectionProperties">Properties for connection</param>
        /// <param name="stateDictionary">Associated state dictionary</param>
        /// <returns>The constructed NetGraph</returns>
        public NetGraph CreateFiltered(string name, Logger logger, NetGraph parent,
            MetaDictionary globalMeta, MetaDictionary meta, Guid rootNode, PropertyBag connectionProperties, Dictionary<string, object> stateDictionary)
        {
            Dictionary<Guid, List<GraphLineEntry>> forwardLines = new Dictionary<Guid, List<GraphLineEntry>>();
            Dictionary<Guid, List<GraphLineEntry>> backwardLines = new Dictionary<Guid, List<GraphLineEntry>>();
            Dictionary<Guid, GraphNodeEntry> nodesByGuid = new Dictionary<Guid, GraphNodeEntry>();
            List<GraphNodeEntry> nodes = new List<GraphNodeEntry>();
            List<GraphLineEntry> lines = new List<GraphLineEntry>();

            lock (_lockObject)
            {
                foreach (GraphNodeEntry n in _nodes)
                {
                    nodesByGuid[n.Id] = n;
                }

                foreach (GraphLineEntry l in _lines)
                {
                    List<GraphLineEntry> forward;
                    List<GraphLineEntry> backward;

                    if (forwardLines.ContainsKey(l.SourceNode))
                    {
                        forward = forwardLines[l.SourceNode];
                    }
                    else
                    {
                        forward = new List<GraphLineEntry>();
                        forwardLines[l.SourceNode] = forward;
                    }


                    if (backwardLines.ContainsKey(l.DestNode))
                    {
                        backward = backwardLines[l.DestNode];
                    }
                    else
                    {
                        backward = new List<GraphLineEntry>();
                        backwardLines[l.DestNode] = backward;
                    }

                    forward.Add(l);
                    backward.Add(l);
                }

                HashSet<Guid> walkedNodes = new HashSet<Guid>();

                walkedNodes.Add(rootNode);

                if (forwardLines.ContainsKey(rootNode))
                {
                    Stack<GraphNodeEntry> nodeStack = new Stack<GraphNodeEntry>();

                    foreach (GraphLineEntry l in forwardLines[rootNode])
                    {
                        nodeStack.Push(nodesByGuid[l.DestNode]);
                    }

                    while (nodeStack.Count > 0)
                    {
                        GraphNodeEntry currNode = nodeStack.Pop();
                        walkedNodes.Add(currNode.Id);

                        if (!(currNode.Factory is PipelineEndpointFactory))
                        {
                            if (forwardLines.ContainsKey(currNode.Id))
                            {
                                List<GraphLineEntry> entries = forwardLines[currNode.Id];

                                foreach (GraphLineEntry entry in entries)
                                {
                                    if (!walkedNodes.Contains(entry.DestNode))
                                    {
                                        nodeStack.Push(nodesByGuid[entry.DestNode]);
                                    }
                                }
                            }

                            if (backwardLines.ContainsKey(currNode.Id))
                            {
                                List<GraphLineEntry> entries = backwardLines[currNode.Id];

                                foreach (GraphLineEntry entry in entries)
                                {
                                    if (!walkedNodes.Contains(entry.SourceNode))
                                    {
                                        nodeStack.Push(nodesByGuid[entry.SourceNode]);
                                    }
                                }
                            }
                        }
                    }

                    if (walkedNodes.Count > 0)
                    {
                        foreach (Guid g in walkedNodes)
                        {
                            nodes.Add(nodesByGuid[g]);
                            if (forwardLines.ContainsKey(g))
                            {
                                foreach (GraphLineEntry l in forwardLines[g])
                                {
                                    if (walkedNodes.Contains(l.DestNode))
                                    {
                                        lines.Add(l);
                                    }
                                }
                            }
                        }
                    }
                }

                return CreateGraph(name, logger, parent, globalMeta, meta, nodes, lines, _props, connectionProperties, stateDictionary);
            }
        }

        /// <summary>
        /// Build a NetGraph object from the nodes
        /// </summary>
        /// <param name="logger">A logger object</param>
        /// <param name="parent">The parent graph, null if not available</param>
        /// <param name="globalMeta">Global meta dictionary</param>
        /// <param name="meta">Local meta dictionary</param>
        /// <param name="connectionProperties">Properties for connection</param>
        /// <returns>The constructed NetGraph</returns>
        public NetGraph Create(Logger logger, NetGraph parent, MetaDictionary globalMeta, MetaDictionary meta, PropertyBag connectionProperties)
        {
            lock (_lockObject)
            {
                return CreateGraph(Name, logger, parent, globalMeta, meta, _nodes, _lines, _props, connectionProperties, new Dictionary<string, object>());
            }
        }

        /// <summary>
        /// Build a NetGraph object from the nodes
        /// </summary>
        /// <param name="name">The name of the graph</param>
        /// <param name="logger">A logger object</param>
        /// <param name="parent">The parent graph, null if not available</param>
        /// <param name="globalMeta">Global meta dictionary</param>
        /// <param name="meta">Local meta dictionary</param>
        /// <param name="connectionProperties">Properties for connection</param>
        /// <returns>The constructed NetGraph</returns>
        public NetGraph Create(string name, Logger logger, NetGraph parent, MetaDictionary globalMeta, MetaDictionary meta, PropertyBag connectionProperties)
        {
            lock (_lockObject)
            {
                return CreateGraph(name, logger, parent, globalMeta, meta, _nodes, _lines, _props, connectionProperties, new Dictionary<string, object>());
            }
        }

        /// <summary>
        /// Get a list of endpoint nodes (ones which are both sources and sinks)
        /// </summary>
        /// <returns>An array containing the endpoint nodes</returns>
        public PipelineEndpointFactory[] GetEndpoints()
        {
            return GetNodes<PipelineEndpointFactory>();
        }

        /// <summary>
        /// Get nodes by their object type, or derived type
        /// </summary>
        /// <typeparam name="T">The factory type to extract</typeparam>
        /// <returns>The list of nodes, empty array of no nodes found</returns>
        public T[] GetNodes<T>() where T : class
        {
            List<T> nodes = new List<T>();

            lock (_lockObject)
            {
                foreach (var n in _nodes)
                {
                    if (n.Factory is T)
                    {
                        nodes.Add(n.Factory as T);
                    }
                }
            }

            return nodes.ToArray();
        }

        /// <summary>
        /// The ID of this factory
        /// </summary>
        public Guid Uuid { get; set; }

        /// <summary>
        /// The name of the netgraph
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Get the list of nodes
        /// </summary>
        public GraphNodeEntry[] Nodes
        {
            get { return _nodes; }
            set
            {
                lock (_lockObject)
                {
                    _nodes = value;
                }
            }
        }

        /// <summary>
        /// Get the list of lines
        /// </summary>
        public GraphLineEntry[] Lines
        {
            get { return _lines; }
            set
            {
                lock (_lockObject)
                {
                    _lines = value;
                }
            }
        }

        /// <summary>
        /// Update the factory from another
        /// </summary>
        /// <param name="factory">The factory to update from</param>
        public void UpdateGraph(NetGraphFactory factory)
        {
            lock (_lockObject)
            {
                _lines = factory.Lines;
                _nodes = factory.Nodes;
                _props.Clear();

                foreach (KeyValuePair<string, string> pair in factory.Properties)
                {
                    _props.Add(pair.Key, pair.Value);
                }
            }
        }

        /// <summary>
        /// Get the graph properties
        /// </summary>
        public Dictionary<string, string> Properties
        {
            get { return _props; }
            set
            {
                lock (_lockObject)
                {
                    _props = value;
                }
            }
        }
    }
}
