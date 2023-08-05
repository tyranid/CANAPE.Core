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
using CANAPE.Security.Cryptography.X509Certificates;
using CANAPE.Utils;
using System;
using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// A layer class to implement a SSL network
    /// </summary>
    public class TlsNetworkLayer : INetworkLayer
    {
        TlsNetworkLayerConfig _config;
        X509Certificate _remoteCert;

        private static ConcurrentDictionary<string, X509Certificate> _certCache =
            new ConcurrentDictionary<string, X509Certificate>();

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="config">Layer configuration</param>
        public TlsNetworkLayer(TlsNetworkLayerConfig config)
        {
            _config = config.Clone();
            Binding = NetworkLayerBinding.Default;
        }

        private bool ValidateRemoteClientConnection(
                Object sender,
                X509Certificate certificate,
                X509Chain chain,
                SslPolicyErrors sslPolicyErrors
                )
        {
            bool ret = true;

            if (_config.VerifyServerCertificate)
            {
                if (sslPolicyErrors != SslPolicyErrors.None)
                {
                    ret = false;
                }
            }

            return ret;
        }

        private bool ValidateRemoteServerConnection(
            Object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors
        )
        {
            bool ret = true;

            if (_config.RequireClientCertificate && _config.VerifyClientCertificate)
            {
                if (sslPolicyErrors != SslPolicyErrors.None)
                {
                    ret = false;
                }
            }

            return ret;
        }

        private static int nameCounter = 0;

        private static void PopulateSslMeta(PropertyBag properties, SslStream stm)
        {
            properties.AddValue("SslProtocol", stm.SslProtocol);
            properties.AddValue("IsSigned", stm.IsSigned);
            properties.AddValue("IsMutallyAuthenticated", stm.IsMutuallyAuthenticated);
            properties.AddValue("IsEncrypted", stm.IsEncrypted);
            properties.AddValue("CipherAlgorithm", stm.CipherAlgorithm);
            properties.AddValue("CipherStrength", stm.CipherStrength);
            properties.AddValue("HashAlgorithm", stm.HashAlgorithm);
            properties.AddValue("HashStrength", stm.HashStrength);

            if (stm.LocalCertificate != null)
            {
                properties.AddValue("LocalCertificate", stm.LocalCertificate);
            }

            if (stm.RemoteCertificate != null)
            {
                properties.AddValue("RemoteCertificate", stm.RemoteCertificate);
                properties.AddValue("KeyExchangeAlgorithm", stm.KeyExchangeAlgorithm);
                properties.AddValue("KeyExchangeStrength", stm.KeyExchangeStrength);
            }
        }

        private IDataAdapter ConnectClient(IDataAdapter adapter, Logger logger, PropertyBag properties, string serverName)
        {
            SslStream sslStream = new SslStream(new DataAdapterToStream(adapter), false, ValidateRemoteClientConnection);

            if (serverName == null)
            {
                // Just generate something
                serverName = Interlocked.Increment(ref nameCounter).ToString();
            }

            X509Certificate2Collection clientCerts = new X509Certificate2Collection();
            bool setReadTimeout = false;
            int oldTimeout = -1;

            foreach (X509Certificate2 clientCert in _config.ClientCertificates)
            {
                clientCerts.Add(clientCert);
            }

            try
            {
                oldTimeout = sslStream.ReadTimeout;
                sslStream.ReadTimeout = _config.Timeout;
                setReadTimeout = true;
            }
            catch (InvalidOperationException)
            {
            }

            sslStream.AuthenticateAsClientAsync(serverName, clientCerts, _config.ClientProtocol, false).Wait();

            if (setReadTimeout)
            {
                sslStream.ReadTimeout = oldTimeout;
            }

            _remoteCert = sslStream.RemoteCertificate;
            if (_remoteCert == null)
            {
                if (!_certCache.TryGetValue(serverName, out _remoteCert))
                {
                    throw new InvalidOperationException(CANAPE.Net.Properties.Resources.SslNetworkLayer_CannotGetServerCertificate);
                }
            }
            else
            {
                _certCache.TryAdd(serverName, _remoteCert);
            }

            logger.LogVerbose(CANAPE.Net.Properties.Resources.SslNetworkLayer_ClientConnectLog,
                sslStream.SslProtocol, _remoteCert.Subject,
                sslStream.IsSigned, sslStream.IsMutuallyAuthenticated, sslStream.IsEncrypted);

            PopulateSslMeta(properties.AddBag("SslClient"), sslStream);

            return new StreamDataAdapter(sslStream, adapter.Description);
        }

        private IDataAdapter ConnectServer(IDataAdapter adapter, Logger logger, PropertyBag properties)
        {
            X509Certificate2 cert = null;

            // If server certificate not specified try and auto generate one
            if (!_config.SpecifyServerCert)
            {
                if (_remoteCert != null)
                {
                    cert = CertificateManager.GetCertificate(_remoteCert);
                }
                else
                {
                    cert = CertificateManager.GetCertificate("CN=localhost");
                }
            }
            else if (_config.ServerCertificate != null)
            {
                cert = _config.ServerCertificate;
            }
            else if (_config.ServerCertificateSubject != null)
            {
                cert = CertificateManager.GetCertificate(_config.ServerCertificateSubject);
            }
            else
            {
                // Ideally shouldn't get here, but not necessarily consistent :)
                cert = CertificateManager.GetCertificate("CN=localhost");
            }

            SslStream sslStream = new SslStream(new DataAdapterToStream(adapter), false, ValidateRemoteServerConnection);
            bool setReadTimeout = false;
            int oldTimeout = -1;

            try
            {
                oldTimeout = sslStream.ReadTimeout;
                sslStream.ReadTimeout = _config.Timeout;
                setReadTimeout = true;
            }
            catch (InvalidOperationException)
            {
            }

            sslStream.AuthenticateAsServerAsync(cert, _config.RequireClientCertificate, _config.ServerProtocol, false).Wait();

            if (setReadTimeout)
            {
                sslStream.ReadTimeout = oldTimeout;
            }

            logger.LogVerbose(Properties.Resources.SslNetworkLayer_ClientLogString,
                sslStream.SslProtocol, sslStream.IsSigned, sslStream.IsMutuallyAuthenticated, sslStream.IsEncrypted);

            PopulateSslMeta(properties.AddBag("SslServer"), sslStream);

            return new StreamDataAdapter(sslStream, adapter.Description);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="server"></param>
        /// <param name="client"></param>
        /// <param name="token"></param>
        /// <param name="logger"></param>
        /// <param name="meta"></param>
        /// <param name="globalMeta"></param>
        /// <param name="properties"></param>
        /// <param name="defaultBinding"></param>
        public void Negotiate(ref IDataAdapter server, ref IDataAdapter client, ProxyToken token, Logger logger,
            MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties, NetworkLayerBinding defaultBinding)
        {
            if (_config.Enabled)
            {
                if (defaultBinding == NetworkLayerBinding.Default)
                {
                    defaultBinding = NetworkLayerBinding.ClientAndServer;
                }

                if (Binding != NetworkLayerBinding.Default)
                {
                    defaultBinding = Binding;
                }

                if ((defaultBinding & NetworkLayerBinding.Client) == NetworkLayerBinding.Client)
                {
                    if (_config.ClientProtocol != SslProtocols.None)
                    {
                        IpProxyToken iptoken = token as IpProxyToken;
                        string serverName = null;

                        if (iptoken != null)
                        {
                            if (!String.IsNullOrWhiteSpace(iptoken.Hostname))
                            {
                                serverName = iptoken.Hostname;
                            }
                            else
                            {
                                serverName = iptoken.Address.ToString();
                            }
                        }
                        client = ConnectClient(client, logger, properties, serverName);
                    }
                }

                if ((defaultBinding & NetworkLayerBinding.Server) == NetworkLayerBinding.Server)
                {
                    if (_config.ServerProtocol != SslProtocols.None)
                    {
                        server = ConnectServer(server, logger, properties);
                    }
                }
            }
        }

        /// <summary>
        /// Get or set the binding mode used
        /// </summary>
        public NetworkLayerBinding Binding
        {
            get; set;
        }
    }
}
