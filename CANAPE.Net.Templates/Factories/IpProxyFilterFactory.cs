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
using CANAPE.Net.Filters;
using CANAPE.Net.Tokens;
using CANAPE.Utils;
using System;
using System.Text.RegularExpressions;

namespace CANAPE.Net.Templates.Factories
{
    /// <summary>
    /// Factory to create an ip proxy filter
    /// </summary>
    public class IpProxyFilterFactory : ProxyFilterFactory
    {
        /// <summary>
        /// The hostname or IP address to filter on (can be a regex)
        /// </summary>
        public string Address { get; set; }

        /// <summary>
        /// Indicates if this is a regular expression or not
        /// </summary>
        public bool IsRegex { get; set; }

        /// <summary>
        /// The UDP/TCP port
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// The type of IP connection
        /// </summary>
        public IpProxyToken.IpClientType ClientType { get; set; }

        /// <summary>
        /// An address to redirect to if this filter matches
        /// </summary>
        public string RedirectAddress { get; set; }

        /// <summary>
        /// A port to redirect to if this filter matches
        /// </summary>
        public int RedirectPort { get; set; }

        /// <summary>
        /// Indicates the filter is disabled
        /// </summary>
        public bool Disabled { get; set; }

        /// <summary>
        /// Create the filter
        /// </summary>
        /// <returns>The proxy filter</returns>
        protected override ProxyFilter OnCreateFilter()
        {
            IpProxyFilter filter = new IpProxyFilter();

            if (IsRegex)
            {
                filter.Address = new Regex(Address, RegexOptions.IgnoreCase);
            }
            else
            {
                filter.Address = GeneralUtils.GlobToRegex(Address);
            }

            filter.Port = Port;
            filter.ClientType = ClientType;
            filter.RedirectAddress = RedirectAddress;
            filter.RedirectPort = RedirectPort;
            filter.Disabled = Disabled;

            return filter;
        }

        /// <summary>
        /// Overridden method to get description
        /// </summary>
        /// <returns>The description</returns>
        public override string ToString()
        {
            bool ssl = false;

            if (Layers != null)
            {
                foreach (var l in Layers)
                {
                    if (l is TlsNetworkLayerFactory)
                    {
                        ssl = (l as TlsNetworkLayerFactory).Config.Enabled;
                        break;
                    }
                }
            }

            return String.Format("Host: {0} - Port {1} - SSL {2} - Enabled {3}", 
                Address, Port, ssl, !Disabled);
        }
    }
}
