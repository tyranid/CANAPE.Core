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
using CANAPE.Net.Tokens;
using CANAPE.Nodes;
using CANAPE.Utils;
using System.Text.RegularExpressions;

namespace CANAPE.Net.Clients
{
    /// <summary>
    /// An IP proxy client which will direct connect from a list of filters, otherwise it will fail
    /// </summary>
    public class FilteredIpProxyClient : IpProxyClient
    {
        private Regex[] _filters;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="filters">List of filters</param>
        public FilteredIpProxyClient(Regex[] filters)
        {
            _filters = filters;
        }

        private bool IsFiltered(IpProxyToken token)
        {
            foreach (Regex re in _filters)
            {
                if (token.Hostname != null)
                {
                    if (re.IsMatch(token.Hostname))
                    {
                        return true;
                    }
                }

                if (re.IsMatch(token.Address.ToString()))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Connect to the required service with the token
        /// </summary> 
        /// <param name="token">The token recevied from proxy</param>
        /// <param name="globalMeta">The global meta</param>
        /// <param name="logger">The logger</param>
        /// <param name="meta">The meta</param>
        /// <param name="properties">Property bag to add any information to</param>
        /// <returns>The connected data adapter</returns>
        public override IDataAdapter Connect(ProxyToken token, Logger logger, MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties)
        {
            IpProxyToken iptoken = token as IpProxyToken;

            if ((iptoken != null) && IsFiltered(iptoken))
            {
                return base.Connect(token, logger, meta, globalMeta, properties);
            }
            else
            {
                token.Status = NetStatusCodes.Blocked;
                return null;
            }
        }
    }
}
