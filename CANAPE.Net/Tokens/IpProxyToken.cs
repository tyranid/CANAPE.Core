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
using System.Net;

namespace CANAPE.Net.Tokens
{
    /// <summary>
    /// Proxy token which indicates an IP address is requested
    /// </summary>
    public class IpProxyToken : ProxyToken
    {
        /// <summary>
        /// Type of client connection
        /// </summary>
        public enum IpClientType
        {
            /// <summary>
            /// TCP Type
            /// </summary>
            Tcp,
            /// <summary>
            /// UDP Type
            /// </summary>
            Udp,
        }

        /// <summary>
        /// Destination address
        /// </summary>
        public IPAddress Address { get; set; }

        /// <summary>
        /// Desintation port
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Destination hostname
        /// </summary>
        public string Hostname { get; set; }

        /// <summary>
        /// Client type
        /// </summary>
        public IpClientType ClientType { get; set; }

        /// <summary>
        /// Whether to attempt IPv6 connection
        /// </summary>
        public bool Ipv6 { get; set; }

        /// <summary>
        /// The original address at time of construction
        /// </summary>
        public IPAddress OriginalAddress { get; private set; }

        /// <summary>
        /// The original port at time of construction
        /// </summary>
        public int OriginalPort { get; private set; }

        /// <summary>
        /// The original hostname at time of construction
        /// </summary>
        public string OriginalHostname { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="properties"></param>
        public override void PopulateBag(PropertyBag properties)
        {
            base.PopulateBag(properties);

            if (Hostname != null)
            {
                properties.AddValue("Endpoint", new DnsEndPoint(Hostname, Port));
                properties.AddValue("Hostname", Hostname);
            }
            else
            {
                properties.AddValue("Endpoint", new IPEndPoint(Address, Port));
                properties.AddValue("Hostname", Address.ToString());
            }

            properties.AddValue("Protocol", ClientType == IpClientType.Tcp ? "TCP" : "UDP");
            properties.AddValue("Port", Port);
            properties.AddValue("Ipv6", Ipv6);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="address"></param>
        /// <param name="hostname"></param>
        /// <param name="port"></param>
        /// <param name="clientType"></param>
        /// <param name="ipv6"></param>
        public IpProxyToken(IPAddress address, string hostname,
            int port, IpClientType clientType, bool ipv6)
        {
            Address = address;
            Hostname = hostname;
            Port = port;
            OriginalAddress = address;
            OriginalHostname = hostname;
            OriginalPort = port;
            ClientType = clientType;
            Ipv6 = ipv6;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="port"></param>
        /// <param name="ipv6"></param>
        /// <returns></returns>
        public static IpProxyToken CreateTcpToken(string hostname, int port, bool ipv6)
        {
            return new IpProxyToken(null, hostname, port, IpClientType.Tcp, ipv6);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="port"></param>
        /// <param name="ipv6"></param>
        /// <returns></returns>
        public static IpProxyToken CreateUdpToken(string hostname, int port, bool ipv6)
        {
            return new IpProxyToken(null, hostname, port, IpClientType.Udp, ipv6);
        }
    }
}
