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
namespace CANAPE.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Specify the hash algorithm when creating a certificate
    /// </summary>
    public enum CertificateHashAlgorithm
    {
        /// <summary>
        /// SHA1
        /// </summary>
        Sha1,
        /// <summary>
        /// SHA256
        /// </summary>
        Sha256,
        /// <summary>
        /// SHA384
        /// </summary>
        Sha384,
        /// <summary>
        /// SHA512
        /// </summary>
        Sha512,
        /// <summary>
        /// MD5
        /// </summary>
        Md5
    }
}
