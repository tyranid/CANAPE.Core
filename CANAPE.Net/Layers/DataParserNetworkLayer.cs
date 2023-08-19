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
using CANAPE.DataFrames;
using CANAPE.Utils;
using System.IO;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// Data parser network layer.
    /// </summary>
    public abstract class DataParserNetworkLayer : DynamicStreamNetworkLayer
    {
        private Stream _server_stream;
        private Stream _client_stream;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.Net.Layers.DataParserNetworkLayer"/> class.
        /// </summary>
        protected DataParserNetworkLayer()
        {
        }

        /// <summary>
        /// Clients the close.
        /// </summary>
        protected sealed override void ClientClose()
        {
            _client_stream.Dispose();
        }

        /// <summary>
        /// Reads the inbound.
        /// </summary>
        /// <returns>The inbound.</returns>
        /// <param name="reader">Reader.</param>
        protected virtual DataFrame ReadInbound(DataReader reader)
        {
            return GenericRead(reader);
        }

        /// <summary>
        /// Clients the can timeout.
        /// </summary>
        /// <returns><c>true</c>, if can timeout was cliented, <c>false</c> otherwise.</returns>
        protected override bool ClientCanTimeout()
        {
            return _client_stream.CanTimeout;
        }

        /// <summary>
        /// Clients the get timeout.
        /// </summary>
        /// <returns>The get timeout.</returns>
        protected override int ClientGetTimeout()
        {
            return _client_stream.ReadTimeout;
        }

        /// <summary>
        /// Clients the set timeout.
        /// </summary>
        /// <param name="timeout">Timeout.</param>
        protected override void ClientSetTimeout(int timeout)
        {
            _client_stream.ReadTimeout = timeout;
        }

        /// <summary>
        /// Servers the can timeout.
        /// </summary>
        /// <returns><c>true</c>, if can timeout was servered, <c>false</c> otherwise.</returns>
        protected override bool ServerCanTimeout()
        {
            return _server_stream.CanTimeout;
        }

        /// <summary>
        /// Servers the get timeout.
        /// </summary>
        /// <returns>The get timeout.</returns>
        protected override int ServerGetTimeout()
        {
            return _server_stream.ReadTimeout;
        }

        /// <summary>
        /// Servers the set timeout.
        /// </summary>
        /// <param name="timeout">Timeout.</param>
        protected override void ServerSetTimeout(int timeout)
        {
            _server_stream.ReadTimeout = timeout;
        }

        /// <summary>
        /// Clients the read.
        /// </summary>
        /// <returns>The read.</returns>
        protected sealed override DataFrame ClientRead()
        {
            try
            {
                return ReadInbound(new DataReader(_client_stream));
            }
            catch (EndOfStreamException)
            {
                return null;
            }
        }

        /// <summary>
        /// Writes the outbound.
        /// </summary>
        /// <param name="frame">Frame.</param>
        /// <param name="writer">Writer.</param>
        protected virtual void WriteOutbound(DataFrame frame, DataWriter writer)
        {
            GenericWrite(frame, writer);
        }

        /// <summary>
        /// Clients the write.
        /// </summary>
        /// <param name="frame">Frame.</param>
        protected override sealed void ClientWrite(DataFrame frame)
        {
            WriteOutbound(frame, new DataWriter(_client_stream));
        }

        /// <summary>
        /// Negotiates the protocol.
        /// </summary>
        /// <returns><c>true</c>, if protocol was negotiated, <c>false</c> otherwise.</returns>
        /// <param name="outboundStream">Outbound stream.</param>
        /// <param name="inboundStream">Inbound stream.</param>
        protected virtual bool NegotiateProtocol(Stream outboundStream, Stream inboundStream)
        {
            return true;
        }

        /// <summary>
        /// Negotiates the protocol.
        /// </summary>
        /// <returns><c>true</c>, if protocol was negotiated, <c>false</c> otherwise.</returns>
        /// <param name="outboundStream">Outbound stream.</param>
        /// <param name="inboundStream">Inbound stream.</param>
        /// <param name="binding">Binding.</param>
        protected virtual bool NegotiateProtocol(Stream outboundStream,
                                                 Stream inboundStream,
                                                 NetworkLayerBinding binding)
        {
            return NegotiateProtocol(outboundStream, inboundStream);
        }

        /// <summary>
        /// Ons the connect.
        /// </summary>
        /// <returns><c>true</c>, if connect was oned, <c>false</c> otherwise.</returns>
        /// <param name="clientStream">Client stream.</param>
        /// <param name="serverStream">Server stream.</param>
        /// <param name="binding">Binding.</param>
        protected override sealed bool OnConnect(Stream clientStream, Stream serverStream, NetworkLayerBinding binding)
        {
            _client_stream = clientStream;
            _server_stream = serverStream;
            return NegotiateProtocol(clientStream, serverStream, binding);
        }

        /// <summary>
        /// Servers the close.
        /// </summary>
        protected override sealed void ServerClose()
        {
            _server_stream.Dispose();
        }

        private static DataFrame GenericRead(DataReader reader)
        {
            byte[] data = reader.ReadBytes(1024, false, false);
            if (data.Length == 0)
            {
                return null;
            }
            return data.ToDataFrame();
        }

        private static void GenericWrite(DataFrame frame, DataWriter writer)
        {
            writer.WriteBytes(frame.ToArray());
        }

        /// <summary>
        /// Reads the outbound.
        /// </summary>
        /// <returns>The outbound.</returns>
        /// <param name="reader">Reader.</param>
        protected virtual DataFrame ReadOutbound(DataReader reader)
        {
            return GenericRead(reader);
        }

        /// <summary>
        /// Servers the read.
        /// </summary>
        /// <returns>The read.</returns>
        protected override sealed DataFrame ServerRead()
        {
            try
            {
                return ReadOutbound(new DataReader(_server_stream));
            }
            catch (EndOfStreamException)
            {
                return null;
            }
        }

        /// <summary>
        /// Writes the inbound.
        /// </summary>
        /// <param name="frame">Frame.</param>
        /// <param name="writer">Writer.</param>
        protected virtual void WriteInbound(DataFrame frame, DataWriter writer)
        {
            GenericWrite(frame, writer);
        }

        /// <summary>
        /// Servers the write.
        /// </summary>
        /// <param name="frame">Frame.</param>
        protected override sealed void ServerWrite(DataFrame frame)
        {
            WriteInbound(frame, new DataWriter(_server_stream));
        }
    }
}
