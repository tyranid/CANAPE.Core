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
using CANAPE.Net.Listeners;
using CANAPE.Utils;
using System;

namespace CANAPE.Net.Templates.Factories
{
    /// <summary>
    /// Base class for IP proxy listeners
    /// </summary>
    public abstract class IpProxyListenerFactory : IProxyListenerFactory
    {
        private bool _anybind;
        private bool _ipv6;
        private int _port;        

        /// <summary>
        /// Get or set whether to bind to all interfaces
        /// </summary>
        public bool AnyBind 
        {
            get { return _anybind; }
            set { _anybind = value; }
        }

        /// <summary>
        /// Get or set whether to bind to IPv6
        /// </summary>
        public bool IPv6
        {
            get { return _ipv6; }
            set { _ipv6 = value; }
        }

        /// <summary>
        /// Get or set the port number
        /// </summary>
        public int Port
        {
            get { return _port; }
            set
            {
                if ((value < 0) || (value > 65535))
                {
                    throw new ArgumentException(Properties.Resources.IpProxyListenerFactory_InvalidPortNumber);
                }

                _port = value;
            }
        }

        /// <summary>
        /// Create the network listener
        /// </summary>
        /// <param name="logger">The logger</param>
        /// <returns>The new network listener</returns>
        public abstract INetworkListener Create(Logger logger); 
    }
}
