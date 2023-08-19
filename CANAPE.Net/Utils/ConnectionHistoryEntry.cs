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
using System;
using System.Collections.Generic;

namespace CANAPE.Net.Utils
{
    /// <summary>
    /// A class which maintains information about a historical connection
    /// </summary>
    public class ConnectionHistoryEntry
    {
        /// <summary>
        /// Textual description of network
        /// </summary>
        public string NetworkDescription { get; private set; }

        /// <summary>
        /// The network guid (which corresponds to packets logged)
        /// </summary>
        public Guid NetId { get; private set; }

        /// <summary>
        /// The connection start time
        /// </summary>
        public DateTime StartTime { get; private set; }

        /// <summary>
        /// The connection end time
        /// </summary>
        public DateTime EndTime { get; private set; }

        /// <summary>
        /// Properties for the connection
        /// </summary>
        public Dictionary<string, object> Properties { get; private set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="networkDescription">Network description</param>
        /// <param name="netId">Network ID</param>
        /// <param name="startTime">Start time of connection</param>
        /// <param name="endtime">End time of connection</param>
        public ConnectionHistoryEntry(string networkDescription, Guid netId, DateTime startTime, DateTime endtime)
        {
            NetworkDescription = networkDescription;
            NetId = netId;
            StartTime = startTime;
            EndTime = endtime;
            Properties = new Dictionary<string, object>();
        }

        /// <summary>
        /// Override for ToString
        /// </summary>
        /// <returns>The connection entry details</returns>
        public override string ToString()
        {
            return String.Format(CANAPE.Net.Properties.Resources.ConnectionHistoryEntry_ToString,
                NetworkDescription, NetId, StartTime, EndTime);
        }
    }
}
