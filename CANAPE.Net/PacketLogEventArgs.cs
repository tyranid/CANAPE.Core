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

namespace CANAPE.Net
{
    /// <summary>
    /// Arguments for filter log packet event
    /// </summary>
    public class PacketLogEventArgs : EventArgs
    {
        /// <summary>
        /// The packet to be logged
        /// </summary>
        public LogPacket Packet { get; set; }

        /// <summary>
        /// Set to true if to be filtered
        /// </summary>
        public bool Filter { get; set; }

        /// <summary>
        /// The graph associated with this packet
        /// </summary>
        public NetGraph Graph { get; private set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="packet">The packet being logged</param>
        /// <param name="graph">The graph associated with this packet</param>
        public PacketLogEventArgs(LogPacket packet, NetGraph graph)
        {
            Packet = packet;
            Graph = graph;
        }
    }
}
