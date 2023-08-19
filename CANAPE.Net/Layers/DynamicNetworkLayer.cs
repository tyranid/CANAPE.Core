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
using CANAPE.Utils;
using System.Collections.Generic;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// A network layer for dynamic code
    /// </summary>
    public class DynamicNetworkLayer : WrappedNetworkLayer<DynamicConfigObject, dynamic>
    {
        private IDataAdapter _client;
        private IDataAdapter _server;
        private IEnumerator<DataFrame> _clientEnum;
        private IEnumerator<DataFrame> _serverEnum;

        private IEnumerable<DataFrame> ReadFrames(IDataAdapter client)
        {
            DataFrame frame = client.Read();
            while (frame != null)
            {
                yield return frame;

                frame = client.Read();
            }
        }

        /// <summary>
        /// Override to supply a generator which reads frames from client endpoint
        /// </summary>
        /// <param name="client">The client data adapter</param>
        /// <returns>An enumerator of data frames</returns>
        protected virtual IEnumerable<DataFrame> ReadClientFrames(IDataAdapter client)
        {
            return ReadFrames(client);
        }

        /// <summary>
        /// Override to supply a generate which read frames from server endpoint
        /// </summary>
        /// <param name="server">The server data adapter</param>
        /// <returns>An enumerator of server frames</returns>
        protected virtual IEnumerable<DataFrame> ReadServerFrames(IDataAdapter server)
        {
            return ReadFrames(server);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="client"></param>
        /// <param name="frame"></param>
        protected virtual void WriteClientFrame(IDataAdapter client, DataFrame frame)
        {
            client.Write(frame);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="server"></param>
        /// <param name="frame"></param>
        protected virtual void WriteServerFrame(IDataAdapter server, DataFrame frame)
        {
            server.Write(frame);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="frame"></param>
        protected override sealed void ClientWrite(DataFrame frame)
        {
            WriteClientFrame(_client, frame);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        protected override DataFrame ClientRead()
        {
            if (_clientEnum.MoveNext())
            {
                return _clientEnum.Current;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void ClientClose()
        {
            _client.Dispose();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="frame"></param>
        protected override void ServerWrite(DataFrames.DataFrame frame)
        {
            WriteServerFrame(_server, frame);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        protected override DataFrames.DataFrame ServerRead()
        {
            if (_serverEnum.MoveNext())
            {
                return _serverEnum.Current;
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        protected override void ServerClose()
        {
            _server.Dispose();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="client"></param>
        /// <param name="server"></param>
        /// <param name="binding"></param>
        /// <returns></returns>
        protected override sealed bool OnConnect(IDataAdapter client, IDataAdapter server, NetworkLayerBinding binding)
        {
            _clientEnum = ReadClientFrames(client).GetEnumerator();
            _serverEnum = ReadServerFrames(server).GetEnumerator();
            _client = client;
            _server = server;

            return true;
        }
    }
}
