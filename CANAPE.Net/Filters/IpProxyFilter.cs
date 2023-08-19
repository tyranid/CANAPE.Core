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
using CANAPE.Net.Tokens;
using CANAPE.Utils;
using System;
using System.Text.RegularExpressions;

namespace CANAPE.Net.Filters
{
    /// <summary>
    /// Proxy filter for IP connections
    /// </summary>
    public class IpProxyFilter : ProxyFilter
    {
        /// <summary>
        /// The hostname or IP address to filter on 
        /// </summary>
        public Regex Address { get; set; }

        /// <summary>
        /// The UDP/TCP port
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Address to redirect to (null or empty means no redirect)
        /// </summary>
        public string RedirectAddress { get; set; }

        /// <summary>
        /// Port to redirect to (0 means no redirect)
        /// </summary>
        public int RedirectPort { get; set; }

        /// <summary>
        /// The type of IP connection
        /// </summary>
        public IpProxyToken.IpClientType ClientType { get; set; }

        /// <summary>
        /// Apply the proxy filter to a token
        /// </summary>
        /// <param name="token">The tokeb</param>
        /// <param name="logger">A logger to log data to</param>
        public override void Apply(ProxyToken token, Logger logger)
        {
            base.Apply(token, logger);
            IpProxyToken t = token as IpProxyToken;

            if (t != null)
            {
                if (!String.IsNullOrWhiteSpace(RedirectAddress))
                {
                    t.Hostname = RedirectAddress;
                }

                if (RedirectPort != 0)
                {
                    t.Port = RedirectPort;
                }
            }
        }

        /// <summary>
        /// Check if the token matches this filter
        /// </summary>
        /// <param name="token">The token to match</param>
        /// <returns>True if it matches</returns>
        public override bool Match(ProxyToken token)
        {
            bool bMatch = base.Match(token);

            if (bMatch)
            {
                if (token is IpProxyToken)
                {
                    IpProxyToken iptoken = (IpProxyToken)token;
                    string hostName = iptoken.Hostname;
                    string ipAddress = iptoken.Address != null ? iptoken.Address.ToString() : "0.0.0.0";

                    bMatch = Address.IsMatch(ipAddress);
                    if (!bMatch)
                    {
                        bMatch = Address.IsMatch(hostName);
                    }

                    if (Port != 0)
                    {
                        if (iptoken.Port != Port)
                        {
                            bMatch = false;
                        }
                    }

                    if (iptoken.ClientType != ClientType)
                    {
                        bMatch = false;
                    }
                }
                else
                {
                    bMatch = false;
                }
            }

            return bMatch;
        }

        /// <summary>
        /// Overridden ToString method
        /// </summary>
        /// <returns>Returns a string</returns>
        public override string ToString()
        {
            return String.Format(CANAPE.Net.Properties.Resources.IpProxyFilter_ToString, Address, Port);
        }
    }
}
