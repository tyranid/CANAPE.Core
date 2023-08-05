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
    /// Event arguments for when a client connects
    /// </summary>
    public class ClientConnectedEventArgs : EventArgs
    {
        /// <summary>
        /// The data adapter associated with the connection
        /// </summary>
        public IDataAdapter DataAdapter { get; private set; }

        /// <summary>
        /// Any other associated data from the listener
        /// </summary>
        public PropertyBag Properties { get; private set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="adapter"></param>
        public ClientConnectedEventArgs(IDataAdapter adapter)
        {
            DataAdapter = adapter;
            Properties = new PropertyBag("Server");
        }
    }

    /// <summary>
    /// Generic interface for a network listener
    /// </summary>
    public interface INetworkListener : IDisposable
    {
        /// <summary>
        /// Start the listener
        /// </summary>
        void Start();
        /// <summary>
        /// Stop the listener
        /// </summary>
        void Stop();

        /// <summary>
        /// Event called when a client connects
        /// </summary>
        event EventHandler<ClientConnectedEventArgs> ClientConnected;
    }
}
