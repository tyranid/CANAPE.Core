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
    /// Proxy client which connects to a fixed stream socket.
    /// </summary>
    public class FixedStreamSocketProxyClient : ProxyClient
    {
        private readonly EndPoint _endPoint;
        private readonly ProtocolType _protocolType;

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="endPoint">The endpoint to connect to.</param>
        /// <param name="protocolType">The protocol type.</param>
        public FixedStreamSocketProxyClient(EndPoint endPoint, ProtocolType protocolType)
        {
            _endPoint = endPoint;
            _protocolType = protocolType;
        }

        /// <summary>
        /// Bind socket. Not Implemented.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="logger"></param>
        /// <param name="meta"></param>
        /// <param name="globalMeta"></param>
        /// <param name="properties"></param>
        /// <returns></returns>
        public override IDataAdapter Bind(ProxyToken token, Logger logger, MetaDictionary meta,
            MetaDictionary globalMeta, PropertyBag properties)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Connect socket.
        /// </summary>
        /// <param name="token">The proxy token (ignored).</param>
        /// <param name="logger">The logger object.</param>
        /// <param name="meta">Connection meta-data.</param>
        /// <param name="globalMeta">Global meta-data.</param>
        /// <param name="properties">Properties for the connection.</param>
        /// <returns>The connected data adapater.</returns>
        public override IDataAdapter Connect(ProxyToken token, Logger logger,
            MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
        {
            IDataAdapter adapter = null;

            try
            {
                Socket socket = new Socket(_endPoint.AddressFamily, SocketType.Stream, _protocolType);
                socket.Connect(_endPoint);
                NetUtils.PopulateBagFromSocket(socket, properties);

                adapter = new StreamSocketDataAdapter(socket);
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
    }
}
