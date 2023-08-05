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
using CANAPE.Net.Protocols.Parser;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace CANAPE.NodeLibrary.Server
{
    /// <summary>
    /// Dns data server config.
    /// </summary>
    public class DnsDataServerConfig
    {
        private static IPAddress VerifyIPAddress(IPAddress address, AddressFamily family)
        {
            if (address.AddressFamily != family)
            {
                throw new ArgumentException(String.Format("Address must be {0} family",
                    family == AddressFamily.InterNetwork ? "IPv4" : "IPv6"), "family");
            }
            return address;
        }

        IPAddress _response_address;
        IPAddress _response_address6;

        /// <summary>
        /// Gets or sets the response address.
        /// </summary>
        /// <value>The response address.</value>
        public IPAddress ResponseAddress { get => _response_address; set => _response_address = VerifyIPAddress(value, AddressFamily.InterNetwork); }
        /// <summary>
        /// Gets or sets the response address6.
        /// </summary>
        /// <value>The response address6.</value>
        public IPAddress ResponseAddress6 { get => _response_address6; set => _response_address6 = VerifyIPAddress(value, AddressFamily.InterNetworkV6); }
        /// <summary>
        /// Gets or sets the reverse dns.
        /// </summary>
        /// <value>The reverse dns.</value>
        public string ReverseDns { get; set; }
        /// <summary>
        /// Gets or sets the time to live.
        /// </summary>
        /// <value>The time to live.</value>
        public uint TimeToLive { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.NodeLibrary.Server.DnsDataServerConfig"/> class.
        /// </summary>
        public DnsDataServerConfig()
        {
            _response_address = IPAddress.Loopback;
            _response_address6 = IPAddress.IPv6Loopback;
            ReverseDns = String.Empty;
            TimeToLive = 1000;
        }
    }

    /// <summary>
    /// Dns data server.
    /// </summary>
    public class DnsDataServer : BasePersistDataEndpoint<DnsDataServerConfig>
    {
        /// <summary>
        /// Run the specified adapter.
        /// </summary>
        /// <returns>The run.</returns>
        /// <param name="adapter">Adapter.</param>
        public override void Run(IDataAdapter adapter)
        {
            DataFrame frame = adapter.Read();

            while (frame != null)
            {
                try
                {
                    DNSPacket packet = DNSPacket.FromArray(frame.ToArray());
                    List<DNSPacket.DNSRRBase> aRecords = new List<DNSPacket.DNSRRBase>();

                    foreach (DNSPacket.DNSQuestion question in packet.Questions)
                    {
                        if ((question.QClass == DNSPacket.DNSClass.IN) || (question.QClass == DNSPacket.DNSClass.AnyClass))
                        {
                            if ((question.QType == DNSPacket.DNSType.A) || (question.QType == DNSPacket.DNSType.AllRecords))
                            {
                                if (Config.ResponseAddress != IPAddress.Any)
                                {
                                    DNSPacket.ADNSRR addr = new DNSPacket.ADNSRR();

                                    addr.Address = new IPAddress(Config.ResponseAddress.GetAddressBytes());

                                    addr.TimeToLive = Config.TimeToLive;
                                    addr.Type = DNSPacket.DNSType.A;
                                    addr.Class = DNSPacket.DNSClass.IN;
                                    addr.Name = question.QName;

                                    aRecords.Add(addr);
                                }
                            }

                            if ((question.QType == DNSPacket.DNSType.AAAA) || (question.QType == DNSPacket.DNSType.AllRecords))
                            {
                                if (Config.ResponseAddress6 != IPAddress.IPv6Any)
                                {
                                    DNSPacket.AAAADNSRR addr = new DNSPacket.AAAADNSRR();

                                    addr.Address = new IPAddress(Config.ResponseAddress6.GetAddressBytes());

                                    addr.TimeToLive = Config.TimeToLive;
                                    addr.Type = DNSPacket.DNSType.AAAA;
                                    addr.Class = DNSPacket.DNSClass.IN;
                                    addr.Name = question.QName;

                                    aRecords.Add(addr);
                                }
                            }

                            if ((question.QType == DNSPacket.DNSType.PTR) || (question.QType == DNSPacket.DNSType.AllRecords))
                            {
                                if (!String.IsNullOrEmpty(Config.ReverseDns) && ((question.QName.EndsWith(".in-addr.arpa.") || question.QName.EndsWith(".ip6.arpa."))))
                                {
                                    DNSPacket.PTRDNSRR addr = new DNSPacket.PTRDNSRR();

                                    addr.Ptr = Config.ReverseDns;
                                    addr.Type = DNSPacket.DNSType.PTR;
                                    addr.Class = DNSPacket.DNSClass.IN;
                                    addr.Name = question.QName;

                                    aRecords.Add(addr);
                                }
                            }
                        }
                    }

                    packet.Query = true;
                    packet.RecursionAvailable = true;
                    if (aRecords.Count > 0)
                    {
                        packet.Answers = aRecords.ToArray();
                        packet.AuthoritiveAnswer = true;
                        packet.ResponseCode = DNSPacket.DNSRCode.NoError;
                    }
                    else
                    {
                        packet.ResponseCode = DNSPacket.DNSRCode.Refused;
                    }

                    adapter.Write(packet.ToArray().ToDataFrame());
                }
                catch (ArgumentException ex)
                {
                    Logger.LogException(ex);
                }

                frame = adapter.Read();
            }
        }

        /// <summary>
        /// Validates the config.
        /// </summary>
        /// <param name="config">Config.</param>
        protected override void ValidateConfig(DnsDataServerConfig config)
        {
            if (config.ResponseAddress.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new ArgumentException("ResponseAddress must be an IPv4 address");
            }

            if (config.ResponseAddress6.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new ArgumentException("ResponseAddress6 must be an IPv6 address");
            }
        }

        /// <summary>
        /// Gets the description.
        /// </summary>
        /// <value>The description.</value>
        public override string Description
        {
            get { return "DNS Server"; }
        }
    }
}
