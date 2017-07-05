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
using System.Security.Cryptography.X509Certificates;

namespace CANAPE.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// X509 Certificate Manager, caches created certs
    /// </summary>
    public static class CertificateManager
    {
        static Dictionary<string, byte[]> _certs = new Dictionary<string, byte[]>();

        /// <summary>
        /// Get a certificate which matches the passed in version
        /// </summary>
        /// <param name="match">The certificate to match</param>
        /// <returns>The certificate for this match</returns>        
        public static X509Certificate2 GetCertificate(X509Certificate match)
        {
            X509Certificate2 ret = null;

            if (match == null)
            {
                throw new ArgumentNullException("match");
            }

            lock (_certs)
            {
                if (_certs.ContainsKey(match.Subject))
                {
                    return new X509Certificate2(_certs[match.Subject], String.Empty, X509KeyStorageFlags.Exportable);
                }
            }

            if (ret == null)
            {
                ret = CertificateUtils.CloneAndSignCertificate(match, GetRootCert(), true);
                if (ret != null)
                {
                    lock (_certs)
                    {
                        _certs[match.Subject] = ret.Export(X509ContentType.Pkcs12, String.Empty);
                    }
                }
            }

            return ret;
        }

        /// <summary>
        /// Get a certificate based on the subject name
        /// </summary>
        /// <param name="subjectName">Subject name for the certificate</param>
        /// <returns>The certificate for this match</returns>        
        public static X509Certificate2 GetCertificate(string subjectName)
        {
            X509Certificate2 ret = null;
            lock (_certs)
            {
                if (_certs.ContainsKey(subjectName))
                {
                    return new X509Certificate2(_certs[subjectName], String.Empty, X509KeyStorageFlags.Exportable);
                }
            }

            if (ret == null)
            {
                DateTime notBefore = DateTime.Now;
                ret = CertificateUtils.CreateCert(GetRootCert(),
                    new X500DistinguishedName(subjectName), null, 1024,
                    CertificateHashAlgorithm.Sha1, notBefore, notBefore.AddYears(10), null);
                if (ret != null)
                {
                    lock (_certs)
                    {
                        _certs[subjectName] = ret.Export(X509ContentType.Pkcs12, String.Empty);
                    }
                }
            }

            return ret;
        }

        private static X509Certificate2 _root_cert;

        /// <summary>
        /// Get the CANAPE root certificate, well attempt to create one if it doesn't exist
        /// </summary>
        /// <returns>The root certificate</returns>
        public static X509Certificate2 GetRootCert()
        {
            if (_root_cert == null)
            {
                _root_cert = CertificateUtils.GenerateCACert("CN=BrokenCA_PleaseFix");
            }

            return _root_cert;
        }

        /// <summary>
        /// Set the CANAPE root CA
        /// </summary>
        /// <param name="rootCert">The root cert</param>
        public static void SetRootCert(X509Certificate2 rootCert)
        {
            if (!rootCert.HasPrivateKey)
            {
                throw new ArgumentException("Root certificate must have a private key");
            }
            _root_cert = rootCert;
        }

        /// <summary>
        /// Set the CANAPE root CA from a PFX file.
        /// </summary>
        /// <param name="filename">Path to a PFX file.</param>
        /// <param name="password">Password for PFX file.</param>
        public static void SetRootCert(string filename, string password)
        {
            SetRootCert(CertificateUtils.ImportFromPFX(filename, password));
        }

        /// <summary>
        /// Set the CANAPE root CA from a PFX file.
        /// </summary>
        /// <param name="filename">Path to a PFX file.</param>
        /// <param name="password">Password for PFX file.</param>
        public static void SetRootCert(string filename)
        {
            SetRootCert(filename, null);
        }
    }
}
