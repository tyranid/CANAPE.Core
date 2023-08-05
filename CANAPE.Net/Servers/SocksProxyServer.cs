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
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace CANAPE.Net.Servers
{
    /// <summary>
    /// Class to implement a SOCKS proxy server
    /// </summary>
    public class SocksProxyServer : ProxyServer
    {
        /// <summary>
        /// 
        /// </summary>
        public enum SupportedVersion
        {
            /// <summary>
            /// 
            /// </summary>
            All,
            /// <summary>
            /// 
            /// </summary>
            Version4,
            /// <summary>
            /// 
            /// </summary>
            Version5,
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="supportedVersion"></param>
        public SocksProxyServer(Logger logger, SupportedVersion supportedVersion) : base(logger)
        {
            _supportedVersion = supportedVersion;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public SocksProxyServer(Logger logger)
            : this(logger, SupportedVersion.All)
        {
        }

        const byte REQUEST_SUCCEEDED = 0x5A;
        const byte REQUEST_FAILED = 0x5B;

        private SupportedVersion _supportedVersion;

        private ushort ReadUShort(Stream stm)
        {
            byte[] data = GeneralUtils.ReadBytes(stm, sizeof(ushort));

            return BitConverter.ToUInt16(data.Reverse().ToArray(), 0);
        }

        private uint ReadUInt(Stream stm)
        {
            byte[] data = GeneralUtils.ReadBytes(stm, sizeof(uint));

            return BitConverter.ToUInt32(data.Reverse().ToArray(), 0);
        }

        private string ReadZString(Stream stm)
        {
            StringBuilder builder = new StringBuilder();
            int b = stm.ReadByte();

            while (b > 0)
            {
                builder.Append((char)b);
                b = stm.ReadByte();
            }

            if (b < 0)
            {
                throw new EndOfStreamException();
            }

            return builder.ToString();
        }

        private ProxyToken HandleSocksv4Request(DataAdapterToStream stm)
        {
            SocksProxyToken ret = null;

            int req = stm.ReadByte();
            ushort port = ReadUShort(stm);
            byte[] addrBytes = GeneralUtils.ReadBytes(stm, 4);
            IPAddress addr = new IPAddress(addrBytes);
            string addrName = addr.ToString();

            // Discard username
            ReadZString(stm);

            if ((addrBytes[0] == 0) && (addrBytes[1] == 0) && (addrBytes[2] == 0) && (addrBytes[3] != 0))
            {
                StringBuilder builder = new StringBuilder();
                _logger.LogVerbose(CANAPE.Net.Properties.Resources.SocksProxyServer_V4AUsed);
                addrName = ReadZString(stm);
                addr = null;
            }

            if (req == 1)
            {
                _logger.LogVerbose(CANAPE.Net.Properties.Resources.SocksProxyServer_V4ConnectionLog, addrName, port);
                ret = new SocksProxyToken(addr, addrName, port, IpProxyToken.IpClientType.Tcp, false, stm, 4);
            }

            return ret;
        }

        private IDataAdapter HandleSocksV4Response(SocksProxyToken token)
        {
            DataAdapterToStream stm = token.Adapter;
            byte[] resp = new byte[8];
            resp[1] = token.Status == NetStatusCodes.Success ? REQUEST_SUCCEEDED : REQUEST_FAILED;

            stm.Write(resp, 0, resp.Length);

            if (token.Status == NetStatusCodes.Success)
            {
                // Clear adapter value so it wont get disposed
                token.Adapter = null;
                return new StreamDataAdapter(stm);
            }
            else
            {
                return null;
            }
        }

        private bool HandleV5Auth(DataAdapterToStream stm)
        {
            int authCount = stm.ReadByte();
            bool foundAuth = false;

            if (authCount > 0)
            {
                byte[] authModes = GeneralUtils.ReadBytes(stm, authCount);
                foreach (byte b in authModes)
                {
                    if (b == 0)
                    {
                        foundAuth = true;
                        break;
                    }
                }
            }

            byte[] ret = new byte[2];

            ret[0] = 5;
            if (foundAuth)
            {
                ret[1] = 0;
            }
            else
            {
                ret[1] = 0xFF;
            }

            stm.Write(ret, 0, ret.Length);

            return foundAuth;
        }

        private ProxyToken HandleV5RequestData(DataAdapterToStream stm)
        {
            SocksProxyToken ret = null;
            IPAddress addr = null;
            string addrName = null;
            bool ipv6 = false;
            ushort port = 0;

            int ver = stm.ReadByte();
            int code = stm.ReadByte();
            stm.ReadByte(); // Reserved
            int type = stm.ReadByte();

            if ((ver == 5) && (code == 1))
            {
                byte[] data = null;

                switch (type)
                {
                    case 1: // IPv4
                        {
                            data = GeneralUtils.ReadBytes(stm, 4);
                            addr = new IPAddress(data);
                            addrName = addr.ToString();
                        }
                        break;
                    case 3: // Domain name
                        {
                            int nameLen = stm.ReadByte();
                            if (nameLen > 0)
                            {
                                data = GeneralUtils.ReadBytes(stm, nameLen);
                                addrName = Encoding.ASCII.GetString(data);
                            }
                        }
                        break;
                    case 4: // IPv6
                        data = GeneralUtils.ReadBytes(stm, 16);
                        addr = new IPAddress(data);
                        addrName = addr.ToString();
                        ipv6 = true;
                        break;
                    default:
                        break;
                }

                port = ReadUShort(stm);

                if ((addrName != null) && (port > 0))
                {
                    _logger.LogVerbose(CANAPE.Net.Properties.Resources.SocksProxyServer_V5ConnectionLog, addrName, port);
                    ret = new SocksProxyToken(addr, addrName, port, IpProxyToken.IpClientType.Tcp, ipv6, stm, 5);
                }
            }

            return ret;
        }

        private IDataAdapter HandleSocksV5Response(SocksProxyToken token)
        {
            DataAdapterToStream stm = token.Adapter;
            byte[] returnData = new byte[10];

            returnData[0] = 5;
            if (token.Status == NetStatusCodes.Success)
            {
                returnData[1] = 0;
            }
            else
            {
                // General failure
                returnData[1] = 1;
            }

            // Write out data in one go, otherwise Java has a habit of breaking
            returnData[2] = 0;
            returnData[3] = 1;
            stm.Write(returnData, 0, returnData.Length);

            if (token.Status == NetStatusCodes.Success)
            {
                // Clear adapter value so it wont get disposed
                token.Adapter = null;
                return new StreamDataAdapter(stm);
            }
            else
            {
                return null;
            }
        }

        private ProxyToken HandleSocksv5Request(DataAdapterToStream stm)
        {
            if (HandleV5Auth(stm))
            {
                return HandleV5RequestData(stm);
            }

            return null;
        }

        private bool IsSupported(int version)
        {
            if (_supportedVersion == SupportedVersion.All)
            {
                return true;
            }
            else if ((version == 4) && (_supportedVersion == SupportedVersion.Version4))
            {
                return true;
            }
            else if ((version == 5) && (_supportedVersion == SupportedVersion.Version5))
            {
                return true;
            }

            return false;
        }

        private ProxyToken HandleConnectRequest(DataAdapterToStream stm)
        {
            ProxyToken ret = null;
            int version = stm.ReadByte();

            if (IsSupported(version))
            {
                if (version == 4)
                {
                    _logger.LogVerbose(CANAPE.Net.Properties.Resources.SocksProxyServer_NewV4ConnectionLog);
                    ret = HandleSocksv4Request(stm);
                }
                else if (version == 5)
                {
                    _logger.LogVerbose(CANAPE.Net.Properties.Resources.SocksProxyServer_NewV5ConnectionLog);
                    ret = HandleSocksv5Request(stm);
                }
            }
            else
            {
                _logger.LogError(CANAPE.Net.Properties.Resources.SocksProxyServer_UnsupportedVersionLog, version);
            }

            return ret;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="adapter"></param>
        /// <param name="globalMeta"></param>
        /// <param name="meta"></param>
        /// <param name="service"></param>
        /// <returns></returns>
        public override ProxyToken Accept(IDataAdapter adapter, MetaDictionary meta, MetaDictionary globalMeta, ProxyNetworkService service)
        {
            DataAdapterToStream stm = new DataAdapterToStream(adapter);

            return HandleConnectRequest(stm);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <param name="client"></param>
        /// <param name="globalMeta"></param>
        /// <param name="meta"></param>
        /// <param name="service"></param>
        /// <returns></returns>
        public override IDataAdapter Complete(ProxyToken token, MetaDictionary meta, MetaDictionary globalMeta, ProxyNetworkService service, IDataAdapter client)
        {
            SocksProxyToken socksToken = (SocksProxyToken)token;

            if (IsSupported(socksToken.Version))
            {
                if (socksToken.Version == 4)
                {
                    return HandleSocksV4Response(socksToken);
                }
                else if (socksToken.Version == 5)
                {
                    return HandleSocksV5Response(socksToken);
                }
                else
                {
                    // We shouldn't get here
                    throw new InvalidOperationException(CANAPE.Net.Properties.Resources.SocksProxyServer_IsSupportedError);
                }
            }
            else
            {
                _logger.LogError(CANAPE.Net.Properties.Resources.SocksProxyServer_UnsupportedTokenVersion, socksToken.Version);
            }

            return null;
        }

        /// <summary>
        /// ToString implementation
        /// </summary>
        /// <returns>Return to string information</returns>
        public override string ToString()
        {
            return "SOCKS Proxy Server";
        }
    }
}
