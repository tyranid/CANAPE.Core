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
using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// The configuration of an SSL Network Layer
    /// </summary>
    public sealed class TlsNetworkLayerConfig
    {
        const int DEFAULT_TIMEOUT = 4000;
        private bool _disableClient;
        private bool _disableServer;
        private List<X509Certificate2> _clientCertificates;
        private int _timeout;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.Net.Layers.SslNetworkLayerConfig"/> class.
        /// </summary>
        /// <param name="disableClient">If set to <c>true</c> disable client.</param>
        /// <param name="disableServer">If set to <c>true</c> disable server.</param>
        public TlsNetworkLayerConfig(bool disableClient, bool disableServer)
        {
            ClientProtocol = disableClient ? SslProtocols.None : SslProtocols.Tls;
            ServerProtocol = disableServer ? SslProtocols.None : SslProtocols.Tls;
            _clientCertificates = new List<X509Certificate2>();
            _disableClient = disableClient;
            _disableServer = disableServer;
            _timeout = DEFAULT_TIMEOUT;
        }

        /// <summary>
        /// 
        /// </summary>
        public TlsNetworkLayerConfig()
            : this(false, false)
        {
        }

        /// <summary>
        /// Whether SSL is enabled at all
        /// </summary>
        public bool Enabled { get; set; }

        /// <summary>
        /// List of client certificates
        /// </summary>
        public IList<X509Certificate2> ClientCertificates
        {
            get
            {
                // If disabled client just return a readonly empty list
                if (_disableClient)
                {
                    return new List<X509Certificate2>().AsReadOnly();
                }

                return _clientCertificates;
            }
        }

        /// <summary>
        /// The server certificate (if not in auto mode). Will be used in preference
        /// to the auto generated ServerCertificateSubject
        /// </summary>
        public X509Certificate2 ServerCertificate
        {
            get; set;
        }

        /// <summary>
        /// The server certificate subject, will generate a certificate on the fly.
        /// </summary>
        public string ServerCertificateSubject
        {
            get; set;
        }

        /// <summary>
        /// Specifies the server cert (makes ServerCertificate valid)
        /// </summary>
        public bool SpecifyServerCert { get; set; }

        /// <summary>
        /// Specifed whether the remote server certificate is verified
        /// Should default to false as this is for testing only
        /// </summary>
        public bool VerifyServerCertificate { get; set; }

        /// <summary>
        /// The client protocol, if SslProtocols.None then doesn't enable SSL
        /// </summary>
        public SslProtocols ClientProtocol { get; set; }

        /// <summary>
        /// The server protocol, if SslProtocols.None then doesn't enable SSL
        /// </summary>
        public SslProtocols ServerProtocol { get; set; }

        /// <summary>
        /// Whether a client certificate is required or not, whether it then
        /// matters what it sends depends on VerifyClientCertificate
        /// </summary>
        public bool RequireClientCertificate { get; set; }

        /// <summary>
        /// Specifed whether the client certificate is verified
        /// Should default to false as this is for testing only
        /// </summary>
        public bool VerifyClientCertificate { get; set; }

        /// <summary>
        /// Timeout for the SSL connection
        /// </summary>
        public int Timeout
        {
            get { return _timeout == 0 ? DEFAULT_TIMEOUT : _timeout; }
            set
            {
                if (_timeout != value)
                {
                    if ((_timeout < 0) && (_timeout != System.Threading.Timeout.Infinite))
                    {
                        throw new ArgumentException();
                    }

                    _timeout = value;
                }
            }
        }

        /// <summary>
        /// Simple deep clone method
        /// </summary>
        /// <returns>The cloned configuration</returns>
        public TlsNetworkLayerConfig Clone()
        {
            return (TlsNetworkLayerConfig)MemberwiseClone();
        }

        /// <summary>
        /// ToString override
        /// </summary>
        /// <returns>A textual description</returns>
        public override string ToString()
        {
            return String.Format(Properties.Resources.SslNetworkLayerConfig_ToString, Enabled);
        }
    }
}
