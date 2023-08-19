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
using CANAPE.NodeFactories;
using CANAPE.Utils;
using System;
using System.Collections.Generic;

namespace CANAPE.Net.Utils
{
    /// <summary>
    /// Class to build a netgraph factory for ease of use with no GUI
    /// </summary>
    public class NetGraphBuilder
    {
        /// <summary>
        /// Factory
        /// </summary>
        NetGraphFactory _graphFactory;

        /// <summary>
        /// Method to determine if either of these nodes matches this line segment
        /// </summary>
        /// <param name="line"></param>
        /// <param name="nodea"></param>
        /// <param name="nodeb"></param>
        /// <returns></returns>
        private bool MatchLine(NetGraphFactory.GraphLineEntry line, BaseNodeFactory nodea, BaseNodeFactory nodeb)
        {
            return ((line.DestNode == nodea.Id) && (line.SourceNode == nodeb.Id))
                    || ((line.DestNode == nodeb.Id) && (line.SourceNode == nodea.Id));
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public NetGraphBuilder()
            : this(new NetGraphFactory())
        {
        }

        /// <summary>
        /// Constructor which takes an existing factory
        /// </summary>
        /// <param name="factory">The factory</param>
        public NetGraphBuilder(NetGraphFactory factory)
        {
            _graphFactory = factory;
        }

        /// <summary>
        /// Add a server node
        /// </summary>
        /// <param name="label">The node label</param>
        /// <param name="guid">Guid of node</param>
        /// <returns>The server endpoint factory</returns>
        public ServerEndpointFactory AddServer(string label, Guid guid)
        {
            ServerEndpointFactory factory = new ServerEndpointFactory(label, guid);

            AddNode(factory);

            return factory;
        }

        /// <summary>
        /// Add a server node
        /// </summary>
        /// <param name="label">The node label</param>
        /// <returns>The server endpoint factory</returns>
        public ServerEndpointFactory AddServer(string label)
        {
            return AddServer(label, Guid.NewGuid());
        }

        /// <summary>
        /// Add a client node
        /// </summary>
        /// <param name="label">Label</param>
        /// <param name="guid">Guid of node</param>
        /// <returns>The client endpoint factory</returns>
        public ClientEndpointFactory AddClient(string label, Guid guid)
        {
            ClientEndpointFactory factory = new ClientEndpointFactory(label, guid);

            AddNode(factory);

            return factory;
        }

        /// <summary>
        /// Add a client node
        /// </summary>
        /// <param name="label">Label</param>        
        /// <returns>The client endpoint factory</returns>
        public ClientEndpointFactory AddClient(string label)
        {
            return AddClient(label, Guid.NewGuid());
        }

        /// <summary>
        /// Add a log node
        /// </summary>
        /// <param name="label">Label of the node</param>
        /// <param name="color">Color of the logged packet data</param>
        /// <param name="tag">Arbitrary string tag</param>
        /// <param name="convertToBytes">Whether to convert all logged packets to bytes only</param>
        /// <param name="guid">Guid of node</param>
        /// <returns>The log packet node factory</returns>
        public LogPacketNodeFactory AddLog(string label, Guid guid, ColorValue color, string tag, bool convertToBytes)
        {
            LogPacketNodeFactory log = new LogPacketNodeFactory(label, guid, color, tag, convertToBytes);

            AddNode(log);

            return log;
        }

        /// <summary>
        /// Add a log node
        /// </summary>
        /// <param name="label">Label of the node</param>
        /// <returns>The log packet node factory</returns>
        public LogPacketNodeFactory AddLog(string label)
        {
            return AddLog(label, Guid.NewGuid(), new ColorValue(0xff, 0xff, 0xff), label, false);
        }

        /// <summary>
        /// Adds the edit.
        /// </summary>
        /// <returns>The edit.</returns>
        /// <param name="label">Label.</param>
        /// <param name="guid">GUID.</param>
        /// <param name="color">Color.</param>
        /// <param name="tag">Tag.</param>
        public EditPacketNodeFactory AddEdit(string label, Guid guid, ColorValue color, string tag)
        {
            return AddNode(new EditPacketNodeFactory(label, guid, ColorValue.White, tag));
        }

        /// <summary>
        /// Adds the edit.
        /// </summary>
        /// <returns>The edit.</returns>
        /// <param name="label">Label.</param>
        public EditPacketNodeFactory AddEdit(string label)
        {
            return AddEdit(label, Guid.NewGuid(), ColorValue.White, label);
        }

        /// <summary>
        /// Add an arbitrary node
        /// </summary>
        /// <param name="factory">The node factory to add</param>
        public T AddNode<T>(T factory) where T : BaseNodeFactory
        {
            List<NetGraphFactory.GraphNodeEntry> nodes = new List<NetGraphFactory.GraphNodeEntry>(_graphFactory.Nodes);

            nodes.Add(new NetGraphFactory.GraphNodeEntry(factory));

            _graphFactory.Nodes = nodes.ToArray();

            return factory;
        }

        /// <summary>
        /// Delete any line which touches this node
        /// </summary>
        /// <param name="factory">The node to delete lines from</param>
        public void DeleteLine(BaseNodeFactory factory)
        {
            List<NetGraphFactory.GraphLineEntry> lines = new List<NetGraphFactory.GraphLineEntry>(_graphFactory.Lines);

            lines.RemoveAll(l => (l.SourceNode == factory.Id) || (l.DestNode == factory.Id));

            _graphFactory.Lines = lines.ToArray();
        }

        /// <summary>
        /// Delete the line between two nodes
        /// </summary>
        /// <param name="nodea">The node factory for the first node</param>
        /// <param name="nodeb">The node factory for the second node</param>
        public void DeleteLine(BaseNodeFactory nodea, BaseNodeFactory nodeb)
        {
            List<NetGraphFactory.GraphLineEntry> lines = new List<NetGraphFactory.GraphLineEntry>(_graphFactory.Lines);

            lines.RemoveAll(l => MatchLine(l, nodea, nodeb));

            _graphFactory.Lines = lines.ToArray();
        }

        /// <summary>
        /// Delete a node
        /// </summary>
        /// <param name="factory">The node to delete</param>
        public void DeleteNode(BaseNodeFactory factory)
        {
            List<NetGraphFactory.GraphNodeEntry> nodes = new List<NetGraphFactory.GraphNodeEntry>(_graphFactory.Nodes);

            nodes.RemoveAll(n => n.Factory == factory);
            DeleteLine(factory);

            _graphFactory.Nodes = nodes.ToArray();
        }

        /// <summary>
        /// Add lines between multiple nodes
        /// </summary>
        /// <param name="nodes">List of nodes to link</param>
        /// <param name="circular">If true then last node is also linked back to start (for 3 nodes or more)</param>
        public void AddLines(bool circular, params BaseNodeFactory[] nodes)
        {
            if (nodes != null)
            {
                for (int i = 0; i < nodes.Length - 1; ++i)
                {
                    AddLine(nodes[i], nodes[i + 1]);
                }

                if (circular && nodes.Length > 2)
                {
                    AddLines(nodes[nodes.Length - 1], nodes[0]);
                }
            }
        }

        /// <summary>
        /// Add lines between multiple nodes
        /// </summary>
        /// <param name="nodes">List of nodes to link</param>
        public void AddLines(params BaseNodeFactory[] nodes)
        {
            AddLines(false, nodes);
        }

        /// <summary>
        /// Add a line between two nodes
        /// </summary>
        /// <param name="nodea">The starting node</param>
        /// <param name="nodeb">The endoing node</param>
        public void AddLine(BaseNodeFactory nodea, BaseNodeFactory nodeb)
        {
            AddLine(nodea, nodeb, null);
        }

        /// <summary>
        /// Add a line between two nodes
        /// </summary>
        /// <param name="nodea">The starting node</param>
        /// <param name="nodeb">The endoing node</param>
        /// <param name="pathName">The line name</param>
        /// <param name="weak">Indicates the line is weak</param>
        public void AddLine(BaseNodeFactory nodea, BaseNodeFactory nodeb, string pathName, bool weak)
        {
            bool matched = false;
            List<NetGraphFactory.GraphLineEntry> lines = new List<NetGraphFactory.GraphLineEntry>(_graphFactory.Lines);

            foreach (var line in lines)
            {
                if (MatchLine(line, nodea, nodeb))
                {
                    // Just set bidirection flag
                    line.BiDirection = true;
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                lines.Add(new NetGraphFactory.GraphLineEntry(nodea.Id, nodeb.Id, false, pathName, false));
            }

            _graphFactory.Lines = lines.ToArray();
        }

        /// <summary>
        /// Add a line between two nodes
        /// </summary>
        /// <param name="nodea">The starting node</param>
        /// <param name="nodeb">The endoing node</param>
        /// <param name="pathName">The line name</param>        
        public void AddLine(BaseNodeFactory nodea, BaseNodeFactory nodeb, string pathName)
        {
            AddLine(nodea, nodeb, pathName, false);
        }

        /// <summary>
        /// Get the netgraph factory
        /// </summary>
        public NetGraphFactory Factory
        {
            get
            {
                return _graphFactory;
            }
        }

        /// <summary>
        /// Create a default proxy graph factory 
        /// </summary>
        /// <returns>The new factory</returns>
        public static NetGraphFactory CreateDefaultProxyGraph()
        {
            return CreateDefaultProxyGraph(null);
        }

        /// <summary>
        /// Create a default proxy graph factory
        /// </summary>
        /// <param name="name">A name to associate with the graph</param>
        /// <returns>The new factory</returns>
        public static NetGraphFactory CreateDefaultProxyGraph(string name)
        {
            string prefix = name != null ? String.Format("{0} - ", name) : String.Empty;
            NetGraphBuilder builder = new NetGraphBuilder();

            var client = builder.AddClient(prefix + "CLIENT", Guid.NewGuid());
            var server = builder.AddServer(prefix + "SERVER", Guid.NewGuid());
            var logOut = builder.AddLog(prefix + "LOGOUT", Guid.NewGuid(),
                                        ColorValue.Pink, "Out", false);
            var logIn = builder.AddLog(prefix + "LOGIN", Guid.NewGuid(),
                                       ColorValue.Powderblue, "In", false);
            var editOut = builder.AddEdit(prefix + "EDITOUT", Guid.NewGuid(), ColorValue.White, "Out");
            var editIn = builder.AddEdit(prefix + "EDITIN", Guid.NewGuid(), ColorValue.White, "In");

            builder.AddLines(server, editOut, logOut, client, editIn, logIn, server);

            return builder.Factory;
        }
    }
}
