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
using CANAPE.DataFrames;
using CANAPE.Utils;
using System;

namespace CANAPE.Nodes
{
    /// <summary>
    /// Event arguments send when logging a packet
    /// </summary>
    public class LogPacketEventArgs : EventArgs
    {
        /// <summary>
        /// The log tag string
        /// </summary>
        public string Tag { get; set; }

        /// <summary>
        /// The unique id of the network it came from
        /// </summary>
        public Guid NetId { get; set; }

        /// <summary>
        /// The frame to log
        /// </summary>
        public DataFrame Frame { get; set; }

        /// <summary>
        /// The color of the log entry
        /// </summary>
        public ColorValue Color { get; set; }

        /// <summary>
        /// The network description
        /// </summary>
        public string NetworkDescription { get; set; }

        /// <summary>
        /// The time which this packet was logged
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="tag">The log tag</param>
        /// <param name="netId">The log network ID</param>
        /// <param name="frame">The log frame</param>
        /// <param name="color">The log colour</param>
        /// <param name="networkDescription">The log description</param>
        public LogPacketEventArgs(string tag, Guid netId, DataFrame frame, ColorValue color, string networkDescription)
        {
            Tag = tag;
            NetId = netId;
            Frame = frame;
            Color = color;
            NetworkDescription = networkDescription;
            Timestamp = DateTime.Now;
        }
    }

    /// <summary>
    /// Log packet pipeline node
    /// </summary>
    public class LogPacketPipelineNode : BasePipelineNode
    {
        /// <summary>
        /// Color of the log entry
        /// </summary>
        public ColorValue Color { get; set; }

        /// <summary>
        /// A textual tag to log
        /// </summary>
        public string Tag { get; set; }

        /// <summary>
        /// If true then all logged frames will be converted to bytes
        /// </summary>
        public bool ConvertToBytes { get; set; }

        /// <summary>
        /// OnInput method
        /// </summary>
        /// <param name="frame"></param>
        protected override void OnInput(DataFrame frame)
        {
            Graph.DoLogPacket(String.IsNullOrWhiteSpace(Tag) ? Name : Tag, Color, frame, ConvertToBytes);

            WriteOutput(frame);
        }

    }
}
