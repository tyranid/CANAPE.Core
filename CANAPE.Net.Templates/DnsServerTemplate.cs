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
using CANAPE.NodeLibrary.Server;
using System.Net;

namespace CANAPE.Net.Templates
{
    /// <summary>
    /// Template for a DNS server
    /// </summary>
    public class DnsServerTemplate : NetServerTemplate<DnsDataServer, DnsDataServerConfig>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public DnsServerTemplate()
        {
            LocalPort = 53;
            UdpEnable = true;
        }

        /// <summary>
        /// DNS respose address.
        /// </summary>
        public string ResponseAddress
        {
            get => ServerFactoryConfig.ResponseAddress.ToString();
            set => ServerFactoryConfig.ResponseAddress = IPAddress.Parse(value);
        }

        /// <summary>
        /// DNS response address IPv6
        /// </summary>
        public string ResponseAddress6
        {
            get => ServerFactoryConfig.ResponseAddress6.ToString();
            set => ServerFactoryConfig.ResponseAddress6 = IPAddress.Parse(value);
        }

        /// <summary>
        /// Reverse DNS name
        /// </summary>
        public string ReverseDns
        {
            get => ServerFactoryConfig.ReverseDns;
            set => ServerFactoryConfig.ReverseDns = value;
        }

        /// <summary>
        /// Response TTL
        /// </summary>
        public uint TimeToLive
        {
            get => ServerFactoryConfig.TimeToLive;
            set => ServerFactoryConfig.TimeToLive = value;
        }
    }
}
