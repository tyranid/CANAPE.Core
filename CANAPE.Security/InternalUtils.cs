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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CANAPE.Security.Cryptography.X509Certificates
{
    internal static class InternalUtils
    {
        public static AsymmetricCipherKeyPair GetBCPrivateKey(this X509Certificate2 cert)
        {
            if (!cert.HasPrivateKey)
            {
                throw new ArgumentException("cert");
            }

            return GetRsaKeyPair(cert.GetRSAPrivateKey());
        }

        /// <summary>
        /// Returns the RSA Key pair for a RSA CryptoServiceProvider
        /// Borrowed this small sample from .NET Crypto Extensions
        /// </summary>
        /// <param name="rsa">RSA algorithm</param>
        /// <returns>RSA key pair</returns>
        private static AsymmetricCipherKeyPair GetRsaKeyPair(RSA rsa)
        {
            RSAParameters rp = rsa.ExportParameters(true);
            BigInteger modulus = new BigInteger(1, rp.Modulus);
            BigInteger pubExp = new BigInteger(1, rp.Exponent);

            RsaKeyParameters pubKey = new RsaKeyParameters(
                false,
                modulus,
                pubExp);

            RsaPrivateCrtKeyParameters privKey = new RsaPrivateCrtKeyParameters(
                modulus,
                pubExp,
                new BigInteger(1, rp.D),
                new BigInteger(1, rp.P),
                new BigInteger(1, rp.Q),
                new BigInteger(1, rp.DP),
                new BigInteger(1, rp.DQ),
                new BigInteger(1, rp.InverseQ));

            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }
    }
}
