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
namespace CANAPE.Net.Templates.Factories
{
    /// <summary>
    /// Base class for TCP clients
    /// </summary>
    public abstract class TcpProxyClientFactory : BaseProxyClientFactory
    {
        /// <summary>
        /// Hostname
        /// </summary>
        protected string _hostname;

        /// <summary>
        /// Port
        /// </summary>
        protected int _port;

        /// <summary>
        /// IPv6 enabled
        /// </summary>
        protected bool _ipv6;

        /// <summary>
        /// Get or set the destination hostname
        /// </summary>
        public string Hostname
        {
            get
            {
                return _hostname;
            }

            set
            {
                if (_hostname != value)
                {
                    _hostname = value;
                }
            }
        }

        /// <summary>
        /// Get or set the port
        /// </summary>
        public int Port
        {
            get
            {
                return _port;
            }

            set
            {
                if (_port != value)
                {
                    _port = value;
                }
            }
        }

        /// <summary>
        /// Get or set whether to use IPv6
        /// </summary>
        public bool IPv6
        {
            get
            {
                return _ipv6;
            }

            set
            {
                if (_ipv6 != value)
                {
                    _ipv6 = value;
                }
            }
        }
    }
}
