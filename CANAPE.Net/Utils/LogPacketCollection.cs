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
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CANAPE.Net.Utils
{
    /// <summary>
    /// Class to hold a collection of packets
    /// </summary>
    public class LogPacketCollection : List<LogPacket>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public LogPacketCollection()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="packets">List of log packets</param>
        public LogPacketCollection(IEnumerable<LogPacket> packets)
            : base(packets)
        {
        }

        private static bool EqualTag(LogPacket packet, string tag)
        {
            if (packet.Tag == null)
            {
                return false;
            }
            return packet.Tag.Equals(tag, StringComparison.CurrentCultureIgnoreCase);
        }

        /// <summary>
        /// Get a list of packets for a tag name
        /// </summary>
        /// <param name="tag">The tag name</param>
        /// <returns>The list of packets</returns>
        public IEnumerable<LogPacket> GetPacketsForTag(string tag)
        {
            List<LogPacket> packets = new List<LogPacket>();

            lock (this)
            {
                foreach (LogPacket packet in this)
                {
                    if (EqualTag(packet, tag))
                    {
                        packets.Add(packet);
                    }
                }
            }

            return packets.AsReadOnly();
        }

        /// <summary>
        /// Get a list of packets for a network connection
        /// </summary>
        /// <param name="netId">The network ID</param>
        /// <returns>The list of packets</returns>
        public IEnumerable<LogPacket> GetPacketsForNetwork(Guid netId)
        {
            List<LogPacket> packets = new List<LogPacket>();

            lock (this)
            {
                foreach (LogPacket packet in this)
                {
                    if (packet.NetId.Equals(netId))
                    {
                        packets.Add(packet);
                    }
                }
            }

            return packets.AsReadOnly();
        }

        /// <summary>
        /// Get the packets for a network id
        /// </summary>
        /// <param name="netId">The network id</param>
        /// <returns>The list of network packets</returns>
        public IEnumerable<LogPacket> GetPacketsForNetwork(string netId)
        {
            if (Guid.TryParse(netId, out Guid g))
            {
                return GetPacketsForNetwork(g);
            }
            else
            {
                return new LogPacket[0];
            }
        }

        /// <summary>
        /// Get the list of network ids in this log
        /// </summary>        
        /// <returns>The list of network ids</returns>
        public IEnumerable<Guid> GetNetworkIds()
        {
            HashSet<Guid> networks = new HashSet<Guid>();

            lock (this)
            {
                foreach (LogPacket packet in this)
                {
                    networks.Add(packet.NetId);
                }
            }

            return networks;
        }

        /// <summary>
        /// Writes to file.
        /// </summary>
        /// <param name="filename">Filename.</param>
        /// <param name="predicate">Predicate.</param>
        public void WriteToFile(string filename, Func<LogPacket, bool> predicate)
        {
            GeneralUtils.WritePacketsToFile(filename, this.Where(predicate));
        }

        /// <summary>
        /// Writes to file only a specific tag.
        /// </summary>
        /// <param name="filename">Filename.</param>
        /// <param name="tag">Tag.</param>
        public void WriteToFile(string filename, string tag)
        {
            WriteToFile(filename, p => EqualTag(p, tag));
        }

        /// <summary>
        /// Writes to file only a specific tag.
        /// </summary>
        /// <param name="filename">Filename.</param>
        public void WriteToFile(string filename)
        {
            GeneralUtils.WritePacketsToFile(filename, this);
        }

        /// <summary>
        /// Reads from file.
        /// </summary>
        /// <returns>The from file.</returns>
        /// <param name="filename">Filename.</param>
        public static LogPacketCollection ReadFromFile(string filename)
        {
            return new LogPacketCollection(GeneralUtils.ReadPacketsFromFile(filename));
        }
    }
}
