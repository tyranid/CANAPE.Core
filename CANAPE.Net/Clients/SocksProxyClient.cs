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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using CANAPE.DataAdapters;
using CANAPE.Net.Tokens;
using CANAPE.Utils;
using CANAPE.Nodes;
using CANAPE.Net.Utils;

namespace CANAPE.Net.Clients
{
    /// <summary>
    /// A ProxyClient to connect to a socks proxy
    /// </summary>
    public class SocksProxyClient : IpProxyClient
    {
        private string  _hostname;
        private int     _port;
        private bool    _ipv6;
        private bool    _sendHostName;
        private SupportedVersion _version;

        /// <summary>
        /// Supported versions for SOCKS proxy client
        /// </summary>
        public enum SupportedVersion
        {
            /// <summary>
            /// Version 5
            /// </summary>
            Version5,
            /// <summary>
            /// Version 4 or 4a (depending on value of _sendHostName)
            /// </summary>
            Version4,
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="hostname">The hostname/ip of the socks server</param>
        /// <param name="port">The port of the socks server</param>
        /// <param name="ipv6">True to try and use IPv6 (if available)</param>
        /// <param name="version">Specify the supported versions</param>
        /// <param name="sendHostName">True to send the hostname to the socks server</param>
        public SocksProxyClient(string hostname, int port, bool ipv6, SupportedVersion version, bool sendHostName)
        {
            _hostname = hostname;
            _port = port;
            _ipv6 = ipv6;
            _version = version;
            _sendHostName = sendHostName;
        }

        private IPAddress GetAddressFromHost(string hostname, bool ipv6)
        {
            IPAddress ret = null;

            if (!IPAddress.TryParse(hostname, out ret))
            {
                IPHostEntry ent = Dns.GetHostEntryAsync(hostname).GetAwaiter().GetResult();

                if ((ent != null) && (ent.AddressList.Length > 0))
                {
                    foreach (IPAddress addr in ent.AddressList)
                    {
                        if (ipv6 && addr.AddressFamily == AddressFamily.InterNetworkV6)
                        {
                            ret = addr;
                            break;
                        }
                        else if (addr.AddressFamily == AddressFamily.InterNetwork)
                        {
                            ret = addr;
                            break;
                        }
                    }
                }
            }
            
            if(ret == null)
            {
                throw new ArgumentException(CANAPE.Net.Properties.Resources.SocksProxyClient_CouldNotGetHost);
            }

            return ret;
        }

        //////////////////////////////////
        // Possible token permutations
        // Address set, no Hostname (use socks4 or socks5 with address)
        // Address set, Hostname set (use socks4a or socks5 with hostname if told to send, else resolve)
        // Address not set, Hostname set (use socks4a or socks5 with hostname if told to send, else resolve)

        private void ConnectVersion4(Stream stm, IpProxyToken token, Logger logger)
        {
            IPAddress address = token.Address;

            if (address == null)
            {
                address = GetAddressFromHost(token.Hostname, false);
            }

            byte[] req = new byte[9];
            req[0] = 4;
            req[1] = 1;
            req[2] = (byte)(token.Port >> 8);
            req[3] = (byte)(token.Port & 0xFF);

            byte[] addrbytes = address.GetAddressBytes();

            req[4] = addrbytes[0];
            req[5] = addrbytes[1];
            req[6] = addrbytes[2];
            req[7] = addrbytes[3];
            
            stm.Write(req, 0, req.Length);

            byte[] resp = GeneralUtils.ReadBytes(stm, 8);

            if (resp[1] == 0x5A)
            {
                token.Status = NetStatusCodes.Success;
            }
            else
            {
                token.Status = NetStatusCodes.ConnectFailure;
            }
        }

        private void ConnectVersion4a(Stream stm, IpProxyToken token, Logger logger)
        {
            byte[] req = new byte[9+token.Hostname.Length+1];
            req[0] = 4;
            req[1] = 1;
            req[2] = (byte)(token.Port >> 8);
            req[3] = (byte)(token.Port & 0xFF);

            req[5] = 0;
            req[4] = 0;
            req[6] = 0;
            req[7] = 0x7F;

            Array.Copy(Encoding.ASCII.GetBytes(token.Hostname), 0, req, 9, token.Hostname.Length);

            stm.Write(req, 0, req.Length);

            byte[] resp = GeneralUtils.ReadBytes(stm, 8);

            if (resp[1] == 0x5A)
            {
                token.Status = NetStatusCodes.Success;
            }
            else
            {
                token.Status = NetStatusCodes.ConnectFailure;
            }
        }

        private void ConnectVersion5(Stream stm, IpProxyToken token, Logger logger)
        {
            byte[] req = new byte[3] { 5, 1, 0 };

            stm.Write(req, 0, req.Length);

            byte[] resp = GeneralUtils.ReadBytes(stm, 2);

            if ((resp[0] == 5) && (resp[1] == 0))
            {
                List<byte> connect = new List<byte>();
                connect.Add(5);
                connect.Add(1);
                connect.Add(0);

                if (_sendHostName && !String.IsNullOrWhiteSpace(token.Hostname))
                {
                    connect.Add(3);
                    connect.Add((byte)token.Hostname.Length);
                    connect.AddRange(new BinaryEncoding().GetBytes(token.Hostname));
                }
                else if(token.Address != null)
                {
                    if (token.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        connect.Add(1);
                    }
                    else if (token.Address.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        connect.Add(4);
                    }
                    else
                    {
                        throw new ArgumentException(CANAPE.Net.Properties.Resources.SocksProxyClient_InvalidProxyToken);
                    }

                    connect.AddRange(token.Address.GetAddressBytes());
                }                
                else
                {
                    throw new ArgumentException(CANAPE.Net.Properties.Resources.SocksProxyClient_InvalidProxyToken2);
                }

                connect.Add((byte)(token.Port >> 8));
                connect.Add((byte)(token.Port & 0xFF));

                stm.Write(connect.ToArray(), 0, connect.Count);

                if (stm.ReadByte() != 5)
                {
                    logger.LogError(CANAPE.Net.Properties.Resources.SocksProxyClient_InvalidV5Response);
                }

                int status = stm.ReadByte();

                // Read out the rest of the data
                stm.ReadByte();
                int addrType = stm.ReadByte();

                switch (addrType)
                {
                    case 1:
                        GeneralUtils.ReadBytes(stm, 4);
                        break;
                    case 3:
                        int len = stm.ReadByte();
                        if (len < 0)
                        {
                            throw new EndOfStreamException(CANAPE.Net.Properties.Resources.SocksProxyClient_EosInDomain);
                        }
                        GeneralUtils.ReadBytes(stm, len);
                        break;
                    case 4:
                        GeneralUtils.ReadBytes(stm, 16);
                        break;
                    default:
                        throw new ArgumentException(CANAPE.Net.Properties.Resources.SocksProxyClient_InvalidAddrType);
                }

                // Port
                GeneralUtils.ReadBytes(stm, 2);

                if (status == 0)
                {
                    token.Status = NetStatusCodes.Success;
                }
                else
                {
                    token.Status = NetStatusCodes.ConnectFailure;
                }
            }
            else
            {
                logger.LogError(CANAPE.Net.Properties.Resources.SocksProxyClient_InvalidV5Response2, resp[0], resp[1]);
                token.Status = NetStatusCodes.ConnectFailure;
            }
        }
        
        /// <summary>
        /// Connection to the socks server
        /// </summary>
        /// <param name="token">The proxy token</param>
        /// <param name="logger">Logger</param>
        /// <param name="globalMeta">Global meta</param>
        /// <param name="meta">Meta</param>
        /// <param name="properties">Property bag to populate</param>
        /// <returns>A connected data adapter, or null if not available</returns>
        /// <exception cref="SocketException">Throw if cannot connect</exception>
        /// <exception cref="ArgumentException">Throw if invalid operation occurs</exception>
        /// <exception cref="EndOfStreamException">Throw if stream ends before reading all data</exception>
        public override IDataAdapter Connect(ProxyToken token, Logger logger, MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
        {
            IDataAdapter ret = null;
            
            if (token is IpProxyToken)
            {
                IpProxyToken iptoken = token as IpProxyToken;
                TcpClient client = new TcpClient();
                
                try
                {
                    client.ConnectAsync(_hostname, _port).Wait();

                    if (_version == SupportedVersion.Version4)
                    {
                        if (_sendHostName && !String.IsNullOrWhiteSpace(iptoken.Hostname))
                        {
                            ConnectVersion4a(client.GetStream(), iptoken, logger);
                        }
                        else
                        {
                            ConnectVersion4(client.GetStream(), iptoken, logger);
                        }
                    }
                    else
                    {
                        ConnectVersion5(client.GetStream(), iptoken, logger);
                    }

                    if (iptoken.Status == NetStatusCodes.Success)
                    {
                        NetUtils.PopulateBagFromSocket(client.Client, properties);

                        ret = new TcpClientDataAdapter(client, IpProxyClient.GetDescription((IpProxyToken)token));
                    }
                }
                catch (SocketException ex)
                {
                    logger.LogException(ex);
                    token.Status = NetStatusCodes.ConnectFailure;
                }
                catch (IOException ex)
                {
                    logger.LogException(ex);
                    token.Status = NetStatusCodes.ConnectFailure;
                }
                finally
                {
                    if (ret == null)
                    {
                        client.Dispose();
                    }
                }
            }
            else
            {
                throw new ArgumentException(CANAPE.Net.Properties.Resources.SocksProxyClient_InvalidProxyToken3);
            }

            return ret;
        }
    }
}
