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
using CANAPE.Net.DataAdapters;
using CANAPE.Net.Tokens;
using CANAPE.Net.Utils;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace CANAPE.Net.Clients
{
    /// <summary>
    /// Proxy client to make a direct IP connection
    /// </summary>
    public class IpProxyClient : ProxyClient
    {
        /// <summary>
        /// Get a description of the token
        /// </summary>
        /// <param name="token">The token</param>
        /// <returns>The string description</returns>
        protected static string GetDescription(IpProxyToken token)
        {
            if (token.Hostname != null)
            {
                return String.Format("{0}:{1}", token.Hostname, token.Port);
            }

            return null;
        }

        private IDataAdapter ConnectUdp(IpProxyToken token, Logger logger, PropertyBag properties)
        {
            IDataAdapter adapter = null;

            try
            {
                UdpClient client = new UdpClient(IsTokenIpV6(token) ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
                IPEndPoint endpoint;

                if (token.Hostname == null)
                {
                    endpoint = new IPEndPoint(token.Address, token.Port);
                }
                else
                {
                    endpoint = new IPEndPoint(
                        Dns.GetHostEntryAsync(token.Hostname).GetAwaiter().GetResult().AddressList[0], token.Port);
                }

                NetUtils.PopulateBagFromSocket(client.Client, properties);

                adapter = new UdpClientDataAdapter(client, GetDescription(token), endpoint);
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

            return adapter;
        }

        private static bool IsTokenIpV6(IpProxyToken token)
        {
            bool ret = false;

            if (NetUtils.OSSupportsIPv6)
            {
                if (token.Ipv6)
                {
                    ret = true;
                }
                else if (token.Hostname == null)
                {
                    ret = token.Address.AddressFamily == AddressFamily.InterNetworkV6;
                }
                else
                {
                    IPAddress addr;
                    if (IPAddress.TryParse(token.Hostname, out addr))
                    {
                        ret = addr.AddressFamily == AddressFamily.InterNetworkV6;
                    }
                }
            }

            return ret;
        }

        private IDataAdapter ConnectTcp(IpProxyToken token, Logger logger, PropertyBag properties)
        {
            IDataAdapter adapter = null;

            try
            {
                bool isIpv6 = IsTokenIpV6(token);

                TcpClient client = new TcpClient(isIpv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);

                if (token.Hostname == null)
                {
                    client.ConnectAsync(token.Address, token.Port).Wait();
                }
                else
                {
                    client.ConnectAsync(token.Hostname, token.Port).Wait();
                }

                NetUtils.PopulateBagFromSocket(client.Client, properties);

                adapter = new TcpClientDataAdapter(client, IpProxyClient.GetDescription(token));
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

            return adapter;
        }

        private IDataAdapter BindTcp(IpProxyToken token, Logger logger, PropertyBag properties)
        {
            TcpListenerDataAdapter adapter = null;

            try
            {
                bool isIpv6 = IsTokenIpV6(token);

                adapter = new TcpListenerDataAdapter(new IPEndPoint(isIpv6 ? IPAddress.IPv6Any : IPAddress.Any, token.Port));
                NetUtils.PopulateBagFromSocket(adapter.Listener.Server, properties);
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

            return adapter;
        }

        /// <summary>
        /// Connect to the required service with the token
        /// </summary> 
        /// <param name="token">The token recevied from proxy</param>
        /// <param name="globalMeta">The global meta</param>
        /// <param name="logger">The logger</param>
        /// <param name="meta">The meta</param>
        /// <param name="properties">Property bag to add any information to</param>
        /// <returns>The connected data adapter</returns>
        public override IDataAdapter Connect(ProxyToken token, Logger logger, MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
        {
            IDataAdapter adapter = null;
            IpProxyToken iptoken = token as IpProxyToken;

            if (iptoken != null)
            {
                if (iptoken.ClientType == IpProxyToken.IpClientType.Tcp)
                {
                    adapter = ConnectTcp(iptoken, logger, properties);
                }
                else if (iptoken.ClientType == IpProxyToken.IpClientType.Udp)
                {
                    adapter = ConnectUdp(iptoken, logger, properties);
                }
                else
                {
                    throw new ArgumentException(CANAPE.Net.Properties.Resources.IpProxyClient_InvalidTokenType);
                }
            }

            return adapter;
        }

        /// <summary>
        /// Bind to the required service with the token
        /// </summary> 
        /// <param name="token">The token recevied from proxy</param>
        /// <param name="globalMeta">The global meta</param>
        /// <param name="logger">The logger</param>
        /// <param name="meta">The meta</param>
        /// <param name="properties">Property bag to add any information to</param>
        /// <returns>The connected data adapter</returns>
        public override IDataAdapter Bind(ProxyToken token, Logger logger, MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
        {
            IDataAdapter adapter = null;
            IpProxyToken iptoken = token as IpProxyToken;

            if (iptoken != null)
            {
                if (iptoken.ClientType == IpProxyToken.IpClientType.Tcp)
                {
                    adapter = BindTcp(iptoken, logger, properties);
                }
                else
                {
                    throw new ArgumentException(CANAPE.Net.Properties.Resources.IpProxyClient_InvalidTokenType);
                }
            }

            return adapter;
        }
    }
}
