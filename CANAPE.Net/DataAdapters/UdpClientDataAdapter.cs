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
using System;
using System.Net;
using System.Net.Sockets;

namespace CANAPE.DataAdapters
{
    /// <summary>
    /// Adapter to wrap a UdpClient
    /// </summary>
    public class UdpClientDataAdapter : BaseDataAdapter
    {
        UdpClient _client;
        IPEndPoint _endpoint;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="client">The UDP client</param>
        /// <param name="hostname">The hostname to connected to</param>
        /// <param name="endpoint">The end point to connect to.</param>
        public UdpClientDataAdapter(UdpClient client, string hostname, IPEndPoint endpoint)
        {
            _client = client;
            _endpoint = endpoint;

            if (hostname != null)
            {
                Description = string.Format("{0}/{1}", hostname, _client.Client.RemoteEndPoint);
            }
            else
            {
                Description = _client.Client.RemoteEndPoint.ToString();
            }
        }

        /// <summary>
        /// Read a frame from the UDP client
        /// </summary>
        /// <returns>A data frame, null on error</returns>
        public override DataFrame Read()
        {
            try
            {
                var result = _client.ReceiveAsync().GetAwaiter().GetResult();
                return result.Buffer.ToDataFrame();
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }

            return null;
        }

        /// <summary>
        /// Write a data frame to the client
        /// </summary>
        /// <param name="frame">The frame to write</param>
        public override void Write(DataFrame frame)
        {
            if (frame != null)
            {
                byte[] data = frame.ToArray();
                _client.SendAsync(data, data.Length, _endpoint).Wait();
            }
        }

        /// <summary>
        /// Method called when disposing
        /// </summary>
        /// <param name="disposing">True for disposing, false for finalizing</param>
        protected override void OnDispose(bool disposing)
        {
            try
            {
                _client.Dispose();
            }
            catch (SocketException)
            {
            }
        }
    }
}
