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
using System;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// Simpler dynamic base network layer class, makes it easier to implement in a class and for python
    /// </summary>
    /// <typeparam name="T">Type of configuration</typeparam>
    /// <typeparam name="R">Type to reference configuration</typeparam>
    public abstract class WrappedNetworkLayer<T, R> : BaseNetworkLayer<T, R>
        where R : class
        where T : class, R, new()
    {
        private class WrapperServerDataAdapter : IDataAdapter
        {
            WrappedNetworkLayer<T, R> _networkLayer;
            string _description;

            public WrapperServerDataAdapter(WrappedNetworkLayer<T, R> networkLayer, string description)
            {
                _networkLayer = networkLayer;
                _description = description;
            }

            public DataFrame Read()
            {
                return _networkLayer.ServerRead();
            }

            public void Write(DataFrame frame)
            {
                _networkLayer.ServerWrite(frame);
            }

            public string Description
            {
                get { return _description; }
            }

            public int ReadTimeout
            {
                get
                {
                    return _networkLayer.ServerGetTimeout();
                }
                set
                {
                    _networkLayer.ServerSetTimeout(value);
                }
            }

            public bool CanTimeout
            {
                get { return _networkLayer.ServerCanTimeout(); }
            }

            public void Dispose()
            {
                _networkLayer.ServerClose();
            }

            public void Reconnect()
            {
                throw new NotImplementedException();
            }
        }

        private class WrapperClientDataAdapter : IDataAdapter
        {
            WrappedNetworkLayer<T, R> _networkLayer;
            string _description;

            public WrapperClientDataAdapter(WrappedNetworkLayer<T, R> networkLayer, string description)
            {
                _networkLayer = networkLayer;
                _description = description;
            }

            public DataFrame Read()
            {
                return _networkLayer.ClientRead();
            }

            public void Write(DataFrame frame)
            {
                _networkLayer.ClientWrite(frame);
            }

            public string Description
            {
                get { return _description; }
            }

            public int ReadTimeout
            {
                get
                {
                    return _networkLayer.ClientGetTimeout();
                }
                set
                {
                    _networkLayer.ClientSetTimeout(value);
                }
            }

            public bool CanTimeout
            {
                get { return _networkLayer.ClientCanTimeout(); }
            }

            public void Dispose()
            {
                _networkLayer.ClientClose();
            }

            public void Reconnect()
            {
                throw new NotImplementedException();
            }
        }

        /// <summary>
        /// Method to override writing for a wrapped client adapter
        /// </summary>
        /// <param name="frame">The wraper to write</param>
        protected abstract void ClientWrite(DataFrame frame);

        /// <summary>
        /// Method to override reading for a wrapped client adapter
        /// </summary>
        /// <returns>A data frame read from the adapter, null on end of stream</returns>
        protected abstract DataFrame ClientRead();

        /// <summary>
        /// Method to override closing for a wrapped client adapter
        /// </summary>
        protected abstract void ClientClose();

        /// <summary>
        /// Method to override setting a timeout for a wrapped client adapter
        /// </summary>
        /// <param name="timeout">The timeout in milliseconds</param>
        protected virtual void ClientSetTimeout(int timeout)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Method to override getting a timeout for a wrapped client adapter
        /// </summary>
        /// <returns>The timeout in milliseconds</returns>
        protected virtual int ClientGetTimeout()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Method to override indicating whether we can timeout or not
        /// </summary>
        /// <returns>True indicates a timeout can be set</returns>
        protected virtual bool ClientCanTimeout()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Method to override writing for a wrapped server adapter
        /// </summary>
        /// <param name="frame">The frame to write</param>
        protected abstract void ServerWrite(DataFrame frame);

        /// <summary>
        /// Method to override reading for a wrapped server adapter
        /// </summary>
        /// <returns>A data frame read from the adapter, null on end of stream</returns>
        protected abstract DataFrame ServerRead();

        /// <summary>
        /// Method to override setting a timeout for a wrapped server adapter
        /// </summary>
        /// <param name="timeout">The timeout in milliseconds</param>
        protected virtual void ServerSetTimeout(int timeout)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Method to override getting a timeout for a wrapped client adapter
        /// </summary>
        /// <returns>The timeout in milliseconds</returns>
        protected virtual int ServerGetTimeout()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Method to override indicating whether we can timeout or not
        /// </summary>
        /// <returns>True indicates a timeout can be set</returns>
        protected virtual bool ServerCanTimeout()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Method to override closing for a wrapped server adapter
        /// </summary>        
        protected abstract void ServerClose();

        /// <summary>
        /// Called on layer setup, allows you to override the clients and server adapters if needed
        /// </summary>
        /// <param name="client">Reference to the client adapter</param>
        /// <param name="server">References to the server adapter</param>
        /// <param name="binding">The current binding</param>
        /// <returns>Returns true if the connection should continue</returns>
        protected abstract bool OnConnect(IDataAdapter client, IDataAdapter server, NetworkLayerBinding binding);

        /// <summary>
        /// Method called on Connect
        /// </summary>
        /// <param name="client">The client adapter</param>
        /// <param name="server">The server adapter</param>
        /// <param name="binding">Binding mode</param>
        protected override sealed void OnConnect(ref IDataAdapter client, ref IDataAdapter server, NetworkLayerBinding binding)
        {
            if (OnConnect(client, server, binding))
            {
                if ((binding & NetworkLayerBinding.Client) == NetworkLayerBinding.Client)
                {
                    client = new WrapperClientDataAdapter(this, client.Description);
                }

                if ((binding & NetworkLayerBinding.Server) == NetworkLayerBinding.Server)
                {
                    server = new WrapperServerDataAdapter(this, server.Description);
                }
            }
        }
    }
}
