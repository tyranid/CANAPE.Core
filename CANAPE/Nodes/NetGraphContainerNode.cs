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
using CANAPE.NodeFactories;
using CANAPE.Utils;
using System;
using System.Collections.Generic;

namespace CANAPE.Nodes
{
    /// <summary>
    /// A node to contain a netgraph
    /// </summary>
    public class NetGraphContainerNode : BasePipelineNode
    {
        /// <summary>
        /// Enumeration to determine direction of flow in the graph
        /// </summary>
        public enum GraphDirection
        {
            /// <summary>
            /// Go from client to server
            /// </summary>
            ClientToServer,

            /// <summary>
            /// Go from server to client
            /// </summary>
            ServerToClient
        }

        private class EventDataAdapter : IDataAdapter
        {
            NetGraphContainerNode _container;
            bool _isClosed;

            public EventDataAdapter(NetGraphContainerNode container)
            {
                _container = container;
            }

            #region IDataAdapter Members

            public DataFrame Read()
            {
                throw new NotImplementedException();
            }

            public void Write(DataFrame frame)
            {
                _container.WriteOutput(frame);
            }

            public string Description
            {
                get { return "Dummy Endpoint"; }
            }

            /// <summary>
            /// Overriden ToString
            /// </summary>
            /// <returns></returns>
            public override string ToString()
            {
                return Description;
            }

            public int ReadTimeout
            {
                get
                {
                    throw new InvalidOperationException();
                }

                set
                {
                    throw new InvalidOperationException();
                }
            }

            public bool CanTimeout
            {
                get
                {
                    return false;
                }
            }

            /// <summary>
            /// Reconnect the data adapter
            /// </summary>
            /// <exception cref="NotSupportedException">Always thrown</exception>
            public virtual void Reconnect()
            {
                throw new NotSupportedException();
            }

            #endregion

            #region IDisposable Members

            public void Dispose()
            {
                if (!_isClosed)
                {
                    _isClosed = true;
                    _container.ShutdownOutputs();
                }
            }

            #endregion
        }

        NetGraph _graph;
        PipelineEndpoint _inputNode;
        PipelineEndpoint _outputNode;
        bool _isDisposed;

        /// <summary>
        /// Get the graph this node contains
        /// </summary>
        public NetGraph ContainedGraph { get { return _graph; } }

        /// <summary>
        /// Indicates whether this is a linked node or not
        /// </summary>
        public bool LinkedNode { get; private set; }

        /// <summary>
        /// Constructor for when created a linked version of the node
        /// </summary>        
        /// <param name="linkedNode">The linked master node</param>                
        /// <param name="logger">The associated logger</param>        
        public NetGraphContainerNode(NetGraphContainerNode linkedNode, Logger logger)
        {
            _graph = linkedNode._graph;

            // Reverse the nodes
            _inputNode = linkedNode._outputNode;
            _outputNode = linkedNode._inputNode;

            _graph.BindEndpoint(_outputNode.Uuid, new EventDataAdapter(this));

            LinkedNode = true;

            // We don't bind logging and editing from the same graph, we assume the master did that
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">Name of the factory</param>
        /// <param name="factory">Factory</param>
        /// <param name="direction">Direction of graph</param>        
        /// <param name="containerGraph">The parent graph</param>
        /// <param name="logger">The logger to use</param>
        /// <param name="stateDictionary">Forwarded state dictionary</param>
        /// <param name="linked">If true then we are creating a linked master node</param>
        public NetGraphContainerNode(string name, NetGraphFactory factory,
            GraphDirection direction, NetGraph containerGraph, Logger logger,
            Dictionary<string, object> stateDictionary, bool linked)
        {
            var clients = factory.GetNodes<ClientEndpointFactory>();
            var servers = factory.GetNodes<ServerEndpointFactory>();

            if ((clients.Length > 0) && (servers.Length > 0))
            {
                Guid outputNode = direction == GraphDirection.ClientToServer
                    ? servers[0].Id : clients[0].Id;
                Guid inputNode = direction == GraphDirection.ClientToServer
                    ? clients[0].Id : servers[0].Id;

                if (linked)
                {
                    _graph = factory.Create(name, logger, containerGraph, containerGraph.GlobalMeta,
                        containerGraph.Meta, containerGraph.ConnectionProperties);
                }
                else
                {
                    _graph = factory.CreateFiltered(name, logger, containerGraph, containerGraph.GlobalMeta,
                        containerGraph.Meta, inputNode, containerGraph.ConnectionProperties, stateDictionary);
                }

                _graph.BindEndpoint(outputNode, new EventDataAdapter(this));

                _inputNode = (PipelineEndpoint)_graph.Nodes[inputNode];
                _inputNode.Hidden = true;

                _outputNode = (PipelineEndpoint)_graph.Nodes[outputNode];
                _outputNode.Hidden = true;
            }
            else
            {
                throw new ArgumentException(CANAPE.Properties.Resources.NetGraphContainerNode_InvalidGraph);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="frame"></param>
        protected override void OnInput(DataFrame frame)
        {
            if (_inputNode != null)
            {
                _inputNode.WriteOutput(frame);
            }
            else
            {
                WriteOutput(frame);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="disposing"></param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (!_isDisposed)
            {
                _isDisposed = true;

                if (!LinkedNode)
                {
                    if (_graph != null)
                    {
                        ((IDisposable)_graph).Dispose();
                        _graph = null;
                    }
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        protected override bool OnShutdown()
        {
            if (_inputNode != null)
            {
                _inputNode.ShutdownOutputs();
            }

            return false;
        }
    }
}