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
    /// Factory to create a log packet node
    /// </summary>    
    public class LogPacketNodeFactory : BaseNodeFactory
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="label">The label of the node</param>
        /// <param name="guid">Unique ID of the node</param>
        /// <param name="color">The color of the log entry to use in a gui</param>
        /// <param name="convertToBytes">True indicates all packets are converted to bytes before being logged</param>
        /// <param name="tag">A textual tag to log</param>
        public LogPacketNodeFactory(string label, Guid guid, ColorValue color, string tag, bool convertToBytes)
            : base(label, guid)
        {
            Color = color;
            Tag = tag;
            ConvertToBytes = convertToBytes;
        }
        /// <summary>
        /// The color of the log entry
        /// </summary>
        public ColorValue Color { get; set; }
        /// <summary>
        /// A textual tag to log
        /// </summary>
        public string Tag { get; set; }
        /// <summary>
        /// True indicates all packets are converted to bytes before being logged
        /// </summary>
        public bool ConvertToBytes { get; set; }

        /// <summary>
        /// Method called when being created
        /// </summary>
        /// <returns>The new node</returns>
        protected override BasePipelineNode OnCreate(Logger logger, NetGraph graph, Dictionary<string, object> stateDictionary)
        {
            LogPacketPipelineNode node = new LogPacketPipelineNode();

            node.Tag = Tag;
            node.Color = Color;
            node.ConvertToBytes = ConvertToBytes;

            return node;
        }
    }
}
