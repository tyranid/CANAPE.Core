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
using CANAPE.Net.Layers;
using CANAPE.Net.Tokens;
using CANAPE.Nodes;
using CANAPE.Utils;
using System;
using System.Net;

namespace CANAPE.Net.Servers
{
    /// <summary>
    /// A proxy server which generates a fixed IP address token on connection
    /// </summary>
    public class FixedProxyServer : ProxyServer
    {
        private class FixedProxyToken : IpProxyToken
        {
            public IDataAdapter Adapter { get; set; }

            public FixedProxyToken(IPAddress address, string hostname, int port,
                IpClientType clientType, bool ipv6, IDataAdapter adapter)
                : base(address, hostname, port, clientType, ipv6)
            {
                Adapter = adapter;
            }

            protected override void OnDispose(bool finalize)
            {
                base.OnDispose(finalize);

                if (Adapter != null)
                {
                    try
                    {
                        Adapter.Dispose();
                    }
                    catch (Exception ex)
                    {
                        Logger.SystemLogger.LogException(ex);
                    }

                    Adapter = null;
                }
            }
        }

        private string _hostName;
        private int _port;
        private IpProxyToken.IpClientType _clientType;
        private bool _ipv6;
        private IPAddress _address;
        private INetworkLayerFactory[] _layers;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="adapter"></param>
        /// <param name="meta"></param>
        /// <param name="globalMeta"></param>
        /// <param name="service"></param>
        /// <returns></returns>
        public override ProxyToken Accept(IDataAdapter adapter, MetaDictionary meta, MetaDictionary globalMeta, ProxyNetworkService service)
        {
            FixedProxyToken token = new FixedProxyToken(_address, _hostName, _port, _clientType, _ipv6, adapter)
            {
                Layers = _layers.CreateLayers(_logger)
            };

            return token;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <param name="meta"></param>
        /// <param name="globalMeta"></param>
        /// <param name="service"></param>
        /// <param name="client"></param>
        /// <returns></returns>
        public override IDataAdapter Complete(ProxyToken token, MetaDictionary meta, MetaDictionary globalMeta, ProxyNetworkService service, IDataAdapter client)
        {
            FixedProxyToken passToken = (FixedProxyToken)token;

            IDataAdapter adapter = passToken.Adapter;
            if (token.Status != NetStatusCodes.Success)
            {
                return null;
            }
            else
            {
                // Set to null to prevent Dispose being called
                passToken.Adapter = null;
                return adapter;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="hostName"></param>
        /// <param name="port"></param>
        /// <param name="clientType"></param>
        /// <param name="ipv6"></param>
        /// <param name="layers"></param>
        public FixedProxyServer(Logger logger, string hostName, int port, IpProxyToken.IpClientType clientType,
            bool ipv6, INetworkLayerFactory[] layers) : base(logger)
        {
            _hostName = hostName;
            _port = port;
            _clientType = clientType;
            _ipv6 = ipv6;
            _layers = layers;

            if (!IPAddress.TryParse(_hostName, out _address))
            {
                _address = null;
            }
        }

        /// <summary>
        /// ToString implementation
        /// </summary>
        /// <returns>Return to string information</returns>
        public override string ToString()
        {
            return Properties.Resources.FixedProxyServer_ToString;
        }
    }
}
