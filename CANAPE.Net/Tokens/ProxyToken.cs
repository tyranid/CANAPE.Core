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
using System;
using CANAPE.Net.Clients;
using CANAPE.Net.Layers;
using CANAPE.NodeFactories;
using CANAPE.Nodes;
using System.Collections.Generic;
using CANAPE.Utils;

namespace CANAPE.Net.Tokens
{
    /// <summary>
    /// Base class for proxy tokens
    /// </summary>
    public class ProxyToken : IDisposable
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public ProxyToken()
        {
            State = new Dictionary<string, object>();
        }

        /// <summary>
        /// Status of connection
        /// </summary>
        public NetStatusCodes Status { get; set; }

        /// <summary>
        /// Gets a textual description of the network
        /// </summary>
        public string NetworkDescription { get; set; }

        /// <summary>
        /// Allows the filter to change the default netgraph to something else
        /// </summary>
        public NetGraphFactory Graph { get; set; }

        /// <summary>
        /// Allows the filter to change the default proxy client
        /// </summary>
        public ProxyClient Client { get; set; }

        /// <summary>
        /// Array of network layers to apply to this connection
        /// </summary>
        public INetworkLayer[] Layers { get; set; }

        /// <summary>
        /// Save some extra general state informations
        /// </summary>
        public Dictionary<string, object> State { get; private set; }

        /// <summary>
        /// Indicates whether this token is for connecting or bindings
        /// </summary>
        public bool Bind { get; set; }

        /// <summary>
        /// An overridable method to populate the property bag with information about this token
        /// </summary>
        /// <param name="properties"></param>      
        public virtual void PopulateBag(PropertyBag properties)
        {
            // Do nothing
        }

        private bool _isDisposed;

        /// <summary>
        /// Overridable method to dispose any resources
        /// </summary>
        /// <param name="finalize">Whether this is running in the finalizer or not</param>
        protected virtual void OnDispose(bool finalize)
        {            
            foreach(KeyValuePair<string, object> pair in State)
            {
                IDisposable disp = pair.Value as IDisposable;

                if(disp != null)
                {
                    disp.Dispose();
                }
            }
        }
        
        /// <summary>
        /// Finalizer
        /// </summary>
        ~ProxyToken()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;
                OnDispose(true);
            }
        }

        /// <summary>
        /// Dispose the token
        /// </summary>
        public void Dispose()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;
                OnDispose(false);
            }
        }
    }
}
