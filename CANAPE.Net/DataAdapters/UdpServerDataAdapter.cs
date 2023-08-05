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
using CANAPE.Net.Listeners;
using System.Net;

namespace CANAPE.Net.DataAdapters
{
    /// <summary>
    /// Data adapter for a UDP server
    /// </summary>
    public class UdpServerDataAdapter : BaseDataAdapter
    {
        UdpNetworkListener _listener;
        IPEndPoint _ep;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="listener">The network listener</param>
        /// <param name="ep">The destination endpoint</param>
        public UdpServerDataAdapter(UdpNetworkListener listener, IPEndPoint ep)
        {
            _listener = listener;
            _ep = ep;
            Description = _ep.ToString();
        }

        /// <summary>
        /// Read a frame from the adapter
        /// </summary>
        /// <returns>The frame</returns>
        public override DataFrame Read()
        {
            byte[] data = _listener.Read(_ep);

            if (data == null)
            {
                return null;
            }

            return data.ToDataFrame();
        }

        /// <summary>
        /// Write a frame to the adapter
        /// </summary>
        /// <param name="frame">The frame</param>
        public override void Write(DataFrame frame)
        {
            if (frame != null)
            {
                _listener.Write(frame.ToArray(), _ep);
            }
        }

        /// <summary>
        /// Called on dispose
        /// </summary>
        /// <param name="disposing">True if disposing</param>
        protected override void OnDispose(bool disposing)
        {
            _listener.CloseConnection(_ep);
        }
    }
}
