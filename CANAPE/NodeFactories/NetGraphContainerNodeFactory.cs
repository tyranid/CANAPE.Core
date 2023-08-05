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
    /// A factory which creates a netgraph container
    /// </summary>    
    public class NetGraphContainerNodeFactory : BaseNodeFactory
    {
        /// <summary>
        /// The direction that this node should bind to 
        /// </summary>
        public NetGraphContainerNode.GraphDirection Direction { get; set; }

        /// <summary>
        /// The graph factory to contain in this node
        /// </summary>
        public NetGraphFactory Factory { get; set; }

        /// <summary>
        /// A linked node factory (if applicable)
        /// </summary>
        public NetGraphContainerNodeFactory LinkedNode { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="guid"></param>
        /// <param name="label"></param>
        /// <param name="factory"></param>
        /// <param name="direction"></param>
        public NetGraphContainerNodeFactory(string label, Guid guid, NetGraphFactory factory, NetGraphContainerNode.GraphDirection direction) : base(label, guid)
        {
            Direction = direction;
            Factory = factory;
        }

        /// <summary>
        /// On Create method
        /// </summary>
        /// <param name="logger">The logger for use during creation</param>
        /// <param name="graph">The containing graph</param>
        /// <param name="stateDictionary">Current state dictionary</param>
        /// <returns></returns>
        protected override BasePipelineNode OnCreate(Logger logger, Nodes.NetGraph graph, Dictionary<string, object> stateDictionary)
        {
            if (Factory == null)
            {
                throw new NodeFactoryException(CANAPE.Properties.Resources.NetGraphContainerFactory_MustSpecifyGraph);
            }

            // Check if we have already created this node as part of a pairing
            if (stateDictionary.ContainsKey(Id.ToString()))
            {
                return (BasePipelineNode)stateDictionary[Id.ToString()];
            }

            NetGraphContainerNode ret = new NetGraphContainerNode(Label, Factory, Direction, graph, logger, stateDictionary, LinkedNode != null);

            if (LinkedNode != null)
            {
                stateDictionary[LinkedNode.Id.ToString()] = new NetGraphContainerNode(ret, logger);
            }

            return ret;
        }
    }
}
