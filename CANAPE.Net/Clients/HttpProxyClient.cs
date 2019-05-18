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
using CANAPE.Net.Layers;
using CANAPE.Net.Tokens;
using CANAPE.Net.Utils;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace CANAPE.Net.Clients
{
    /// <summary>
    /// HTTP Proxy client
    /// </summary>
    public class HttpProxyClient : IpProxyClient
    {
        private string _hostname;
        private int _port;
        private bool _ipv6;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="hostname">Hostname to connect to</param>
        /// <param name="port">Port</param>
        /// <param name="ipv6">True for IPv6</param>
        public HttpProxyClient(string hostname, int port, bool ipv6)
        {
            _hostname = hostname;
            _port = port;
            _ipv6 = ipv6;
        }

        private static void ConnectWithFullHttpProxyToken(Stream stm, FullHttpProxyToken token, Logger logger)
        {
            // Don't actually need to do anything just yet
            token.Status = NetStatusCodes.Success;
        }

        private static void ConnectWithHttpProxyToken(Stream stm, HttpProxyToken token, Logger logger)
        {
            token.IsHTTPProxyClient = true;

            if (token.Connect)
            {
                // Send original CONNECT headers
                StringBuilder builder = new StringBuilder();
                foreach (var s in token.Headers)
                {
                    builder.Append(s);
                }

                byte[] data = GeneralUtils.MakeByteArray(builder.ToString());

                stm.Write(data, 0, data.Length);

                builder.Clear();

                // Read out response headers
                while (true)
                {
                    string nextLine = GeneralUtils.ReadLine(stm);

                    builder.Append(nextLine);

                    if (nextLine.Trim().Length == 0)
                    {
                        break;
                    }
                }

                // Smuggle data back to server
                token.Response = GeneralUtils.MakeByteArray(builder.ToString());
            }

            token.Status = NetStatusCodes.Success;
        }

        private static void ConnectWithIpProxyToken(Stream stm, IpProxyToken token, Logger logger)
        {
            string hostname = token.Hostname ?? token.Address.ToString();
            string req = string.Format("CONNECT {0}:{1} HTTP/1.0\r\n\r\n", hostname, token.Port);
            byte[] reqBytes = Encoding.ASCII.GetBytes(req);

            stm.Write(reqBytes, 0, reqBytes.Length);

            List<string> headers = new List<string>();

            // Read out response headers
            while (true)
            {
                string nextLine = GeneralUtils.ReadLine(stm);

                headers.Add(nextLine);

                if (nextLine.Trim().Length == 0)
                {
                    break;
                }
            }

            if (headers.Count > 0)
            {
                string[] vals = headers[0].Split(' ');
                int res = 0;
                if (vals.Length >= 2)
                {
                    if (int.TryParse(vals[1], out res) && (res == 200))
                    {
                        token.Status = NetStatusCodes.Success;
                    }
                    else
                    {
                        logger.LogError(CANAPE.Net.Properties.Resources.HttpProxyClient_ErrorOnConnect, res, hostname, token.Port);
                    }
                }
                else
                {
                    logger.LogError(CANAPE.Net.Properties.Resources.HttpProxyClient_InvalidResponse);
                }
            }
            else
            {
                logger.LogError(CANAPE.Net.Properties.Resources.HttpProxyClient_NoResponse);
            }
        }

        private class FullHttpProxyDataAdapter : TcpClientDataAdapter
        {
            MemoryStream _requestData;
            bool _waitingForHeader;
            string _destHostname;
            int _destPort;
            Logger _logger;

            public FullHttpProxyDataAdapter(TcpClient client, FullHttpProxyToken token, string description, Logger logger)
                : base(client, description)
            {
                _requestData = new MemoryStream();
                _destHostname = token.Hostname;
                _destPort = token.Port;
                _logger = logger;
                _waitingForHeader = true;
            }


            public override void Write(DataFrame frame)
            {
                if (_waitingForHeader)
                {
                    byte[] data = frame.ToArray();

                    _requestData.Write(data, 0, data.Length);
                    string headers = BinaryEncoding.Instance.GetString(_requestData.ToArray());

                    int nlIndex = headers.IndexOf('\n');

                    if (nlIndex >= 0)
                    {
                        string[] val = headers.Substring(0, nlIndex).Split(new char[] { ' ' }, 3);

                        if (val.Length > 1)
                        {
                            if (_destPort == 80)
                            {
                                val[1] = String.Format("http://{0}{1}", _destHostname, val[1]);
                            }
                            else
                            {
                                val[1] = String.Format("http://{0}:{1}{2}", _destHostname, _destPort, val[1]);
                            }
                        }

                        _waitingForHeader = false;
                        _requestData = null;

                        base.Write((String.Join(" ", val) + headers.Substring(nlIndex)).ToDataFrame());
                    }
                }
                else
                {
                    base.Write(frame);
                }
            }
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
            IDataAdapter ret = null;

            token.Status = NetStatusCodes.ConnectFailure;

            if ((token is IpProxyToken) && ((IpProxyToken)token).ClientType == IpProxyToken.IpClientType.Tcp)
            {
                TcpClient client = new TcpClient();

                try
                {
                    client.ConnectAsync(_hostname, _port).Wait();

                    if (token is FullHttpProxyToken)
                    {
                        bool binary = false;

                        if ((token.Layers != null) && (token.Layers.Length > 0))
                        {
                            foreach (INetworkLayer layer in token.Layers)
                            {
                                // Find a binding layer
                                if (layer.Binding == NetworkLayerBinding.Client
                                    || layer.Binding == NetworkLayerBinding.ClientAndServer
                                    || layer.Binding == NetworkLayerBinding.Default)
                                {
                                    if (!(layer is HttpNetworkLayer))
                                    {
                                        binary = true;
                                    }

                                    break;
                                }
                            }
                        }

                        if (!binary)
                        {
                            ret = new FullHttpProxyDataAdapter(client, (FullHttpProxyToken)token, IpProxyClient.GetDescription((IpProxyToken)token), logger);
                            NetUtils.PopulateBagFromSocket(client.Client, properties);
                            token.Status = NetStatusCodes.Success;
                        }
                        else
                        {
                            ConnectWithIpProxyToken(client.GetStream(), (IpProxyToken)token, logger);
                            if (token.Status == NetStatusCodes.Success)
                            {
                                NetUtils.PopulateBagFromSocket(client.Client, properties);
                                ret = new TcpClientDataAdapter(client, IpProxyClient.GetDescription((IpProxyToken)token));
                            }
                        }
                    }
                    else
                    {
                        if (token is HttpProxyToken)
                        {
                            ConnectWithHttpProxyToken(client.GetStream(), (HttpProxyToken)token, logger);
                        }
                        else
                        {
                            ConnectWithIpProxyToken(client.GetStream(), (IpProxyToken)token, logger);
                        }

                        if (token.Status == NetStatusCodes.Success)
                        {
                            NetUtils.PopulateBagFromSocket(client.Client, properties);
                            ret = new TcpClientDataAdapter(client, IpProxyClient.GetDescription((IpProxyToken)token));
                        }
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
                throw new ArgumentException(CANAPE.Net.Properties.Resources.HttpProxyClient_InvalidProxyToken);
            }

            return ret;
        }
    }
}
