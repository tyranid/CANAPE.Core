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
using CANAPE.Utils;
using System;

namespace CANAPE.Net.Listeners
{
    /// <summary>
    /// A network listener you can create arbitrary connections for
    /// </summary>
    public class ManualNetworkListener : INetworkListener
    {
        Logger _logger;
        string _name;

        /// <summary>
        /// Constructor
        /// </summary>
        public ManualNetworkListener()
        {
            _name = Properties.Resources.ManualNetworkListener_Anonymous;
        }

        /// <summary>
        /// Constructor with name
        /// </summary>
        /// <param name="name">The name of the listener</param>
        public ManualNetworkListener(string name)
        {
            _name = name;
        }

        /// <summary>
        /// 
        /// </summary>
        public void Start()
        {
            // Don't need to do anything
        }

        /// <summary>
        /// 
        /// </summary>
        public void Stop()
        {
            // Don't need to do anything
        }

        /// <summary>
        /// 
        /// </summary>
        public event EventHandler<ClientConnectedEventArgs> ClientConnected;

        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            // Don't need to do anything
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="da"></param>
        public void CreateConnection(IDataAdapter da)
        {
            if (ClientConnected != null)
            {
                _logger.LogVerbose(Properties.Resources.ManualNetworkListener_CreateLogString);

                ClientConnected.Invoke(this, new ClientConnectedEventArgs(da));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public ManualNetworkListener(Logger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// ToString implementation
        /// </summary>
        /// <returns>Return the listener information</returns>
        public override string ToString()
        {
            return _name;
        }
    }
}
