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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using SystemX509 = System.Security.Cryptography.X509Certificates;

namespace CANAPE.Security.Cryptography.X509Certificates
{
    internal static class CertificateBuilder
    {
        /// <summary>
        /// Create a new managed RSA key, persisted into a provider
        /// </summary>
        /// <param name="keySize">Size of key to create</param>
        /// <param name="random">Specify the secure random number generator.</param>
        /// <returns>The new key</returns>
        public static AsymmetricCipherKeyPair CreateRSAKey(int keySize, SecureRandom random)
        {
            RsaKeyPairGenerator keygen = new RsaKeyPairGenerator();
            KeyGenerationParameters keygen_params = new KeyGenerationParameters(random, keySize);
            keygen.Init(keygen_params);
            return keygen.GenerateKeyPair();
        }

        private const string szOID_AUTHORITY_KEY_IDENTIFIER2 = "2.5.29.35";

        private static string HashAlgorithmToName(CertificateHashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {

                case CertificateHashAlgorithm.Sha1:
                    return "SHA1WITHRSA";
                case CertificateHashAlgorithm.Sha256:
                    return "SHA256WITHRSA";
                case CertificateHashAlgorithm.Sha384:
                    return "SHA384WITHRSA";
                case CertificateHashAlgorithm.Sha512:
                    return "SHA512WITHRSA";
                case CertificateHashAlgorithm.Md5:
                    return "MD5WITHRSA";
                default:
                    throw new ArgumentException("hashAlgorithm");
            }
        }

        private static ISignatureFactory CreateSignatureFactory(CertificateHashAlgorithm hash_algorithm, AsymmetricCipherKeyPair key, SecureRandom random)
        {
            return new Asn1SignatureFactory(HashAlgorithmToName(hash_algorithm), key.Private, random);
        }

        ///// <summary>
        ///// Create a new certificate
        ///// </summary>
        ///// <param name="issuer">Issuer certificate, if null then self-sign</param>
        ///// <param name="subjectName">Subject name</param>
        ///// <param name="serialNumber">Serial number of certificate, if null then will generate a new one</param>
        ///// <param name="keySize">Size of RSA key</param>
        ///// <param name="notBefore">Start date of certificate</param>
        ///// <param name="notAfter">End date of certificate</param>
        ///// <param name="extensions">Array of extensions, if null then no extensions</param>
        ///// <param name="hashAlgorithm">Specify the signature hash algorithm</param>
        ///// <returns>The created X509 certificate</returns>
        public static SystemX509.X509Certificate2 CreateCert(SystemX509.X509Certificate2 issuer, SystemX509.X500DistinguishedName subjectName,
            byte[] serialNumber, int keySize, CertificateHashAlgorithm hashAlgorithm, DateTime notBefore,
            DateTime notAfter, SystemX509.X509ExtensionCollection extensions)
        {
            SecureRandom random = new SecureRandom();
            X509V3CertificateGenerator builder = new X509V3CertificateGenerator();
            AsymmetricCipherKeyPair bcSubjectKey = CreateRSAKey(keySize, random);
            AsymmetricCipherKeyPair bcSignKey = issuer == null ? bcSubjectKey : issuer.GetBCPrivateKey();

            if (bcSignKey == null)
            {
                throw new ArgumentException("issuer");
            }

            X509Name issuerNameObj = issuer == null ? X509Name.GetInstance(Asn1Object.FromByteArray(subjectName.RawData))
                : X509Name.GetInstance(Asn1Object.FromByteArray(issuer.SubjectName.RawData));
            X509Name subjectNameObj = X509Name.GetInstance(Asn1Object.FromByteArray(subjectName.RawData));

            BigInteger subjectSerial = new BigInteger(1, serialNumber != null ? serialNumber : Guid.NewGuid().ToByteArray());
            BigInteger issuerSerial = issuer == null ? subjectSerial : new BigInteger(1, issuer.GetSerialNumber());

            builder.SetIssuerDN(issuerNameObj);
            builder.SetSubjectDN(subjectNameObj);
            builder.SetSerialNumber(subjectSerial);
            builder.SetNotBefore(notBefore.ToUniversalTime());
            builder.SetNotAfter(notAfter.ToUniversalTime());
            builder.SetPublicKey(bcSubjectKey.Public);

            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcSignKey.Public);
            AuthorityKeyIdentifier authKeyId = new AuthorityKeyIdentifier(info, new GeneralNames(new GeneralName(issuerNameObj)), issuerSerial);
            SubjectKeyIdentifier subjectKeyid = new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcSubjectKey.Public));

            builder.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, true, authKeyId);
            builder.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, true, subjectKeyid);

            if (extensions != null)
            {
                foreach (SystemX509.X509Extension ext in extensions)
                {
                    if (!ext.Oid.Value.Equals(X509Extensions.AuthorityKeyIdentifier.Id)
                        && !ext.Oid.Value.Equals(X509Extensions.SubjectKeyIdentifier.Id)
                        && !ext.Oid.Value.Equals(szOID_AUTHORITY_KEY_IDENTIFIER2))
                    {
                        Asn1InputStream istm = new Asn1InputStream(ext.RawData);
                        Asn1Object obj = istm.ReadObject();
                        builder.AddExtension(ext.Oid.Value, ext.Critical, obj);
                    }
                }
            }

            X509Certificate cert = builder.Generate(CreateSignatureFactory(hashAlgorithm, bcSignKey, random));

            Pkcs12StoreBuilder pkcs = new Pkcs12StoreBuilder();
            Pkcs12Store store = pkcs.Build();
            X509CertificateEntry entry = new X509CertificateEntry(cert);
            store.SetCertificateEntry("main", entry);

            AsymmetricKeyEntry key_entry = new AsymmetricKeyEntry(bcSubjectKey.Private);
            store.SetKeyEntry("main", key_entry, new[] { entry });
            MemoryStream stm = new MemoryStream();
            store.Save(stm, new char[0], new SecureRandom());
            return new SystemX509.X509Certificate2(stm.ToArray(), String.Empty, SystemX509.X509KeyStorageFlags.Exportable);
        }
    }
}
