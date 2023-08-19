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
using System.Net;

namespace CANAPE.Net.Tokens
{
    internal class SocksProxyToken : IpProxyToken
    {
        public DataAdapterToStream Adapter { get; set; }

        public int Version { get; private set; }

        public SocksProxyToken(IPAddress address, string hostname,
            int port, IpClientType clientType, bool ipv6,
            DataAdapterToStream adapter, int version)
            : base(address, hostname, port, clientType, ipv6)
        {
            Adapter = adapter;
            Version = version;
        }

        protected override void OnDispose(bool finalize)
        {
            base.OnDispose(finalize);

            if (Adapter != null)
            {
                try
                {
                    Adapter.Dispose();
                }
                catch (Exception ex)
                {
                    Logger.SystemLogger.LogException(ex);
                }

                Adapter = null;
            }
        }
    }
}
