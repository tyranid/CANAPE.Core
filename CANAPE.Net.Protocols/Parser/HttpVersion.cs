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
using System.Globalization;
using System.Text.RegularExpressions;

namespace CANAPE.Net.Protocols.Parser
{
    /// <summary>
    /// The version of a HTTP request
    /// </summary>
    public struct HttpVersion
    {
        /// <summary>
        /// Parse a string to a version
        /// </summary>
        /// <param name="version">The version string (should be HTTP/X.Y)</param>
        /// <returns>The version as parsed</returns>
        /// <exception cref="FormatException">Thrown if the string is not a valid HTTP version</exception>
        public static HttpVersion Parse(string version)
        {
            HttpVersion ret;

            if (TryParse(version, out ret))
            {
                return ret;
            }
            else
            {
                throw new FormatException(Properties.Resources.HttpVersion_InvalidVersionString);
            }
        }

        /// <summary>
        /// Try and parse a string to a version
        /// </summary>
        /// <param name="version">The version string (should be HTTP/X.Y)</param>
        /// <param name="ret">The output parameter for the version</param>
        /// <returns>True if successfully parsed the verison</returns>        
        public static bool TryParse(string version, out HttpVersion ret)
        {
            Regex re = new Regex(@"^http/([0-9])+\.([0-9]+)$", RegexOptions.IgnoreCase);
            Match m = re.Match(version);
            ret = new HttpVersion();
            bool success = false;

            if (m.Success)
            {
                int major;
                int minor;

                if (int.TryParse(m.Groups[1].Value, out major) && int.TryParse(m.Groups[2].Value, out minor))
                {
                    ret = new HttpVersion(major, minor);
                    success = true;
                }
            }

            return success;
        }

        /// <summary>
        /// Returns true if this is version 1.0
        /// </summary>
        public bool IsVersion10 { get { return Major == 1 && Minor == 0; } }

        /// <summary>
        /// Returns true if this is version 1.1
        /// </summary>
        public bool IsVersion11 { get { return Major == 1 && Minor == 1; } }

        /// <summary>
        /// Returns true if this is an unknown version
        /// </summary>
        public bool IsVersionUnknown { get { return Major == 0 && Minor == 0; } }

        /// <summary>
        /// Get a version 1.0 object
        /// </summary>
        public static HttpVersion Version10 { get { return new HttpVersion(1, 0); } }

        /// <summary>
        /// Get a version 1.1 object
        /// </summary>
        public static HttpVersion Version11 { get { return new HttpVersion(1, 1); } }

        /// <summary>
        /// Get an unknown version object
        /// </summary>
        public static HttpVersion VersionUnknown { get { return new HttpVersion(0, 0); } }

        /// <summary>
        /// Overridden Equals
        /// </summary>
        /// <param name="obj">The object to check against</param>
        /// <returns>True if the object is equal</returns>
        public override bool Equals(object obj)
        {
            if (obj is HttpVersion)
            {
                HttpVersion ver = (HttpVersion)obj;

                return Major == ver.Major && Minor == ver.Minor;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Overridden hash code
        /// </summary>
        /// <returns>The hash code</returns>
        public override int GetHashCode()
        {
            return Major.GetHashCode() ^ Minor.GetHashCode();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="major">The major version</param>
        /// <param name="minor">The minor version</param>
        public HttpVersion(int major, int minor)
        {
            Major = major;
            Minor = minor;
        }

        /// <summary>
        /// The major version
        /// </summary>
        public readonly int Major;

        /// <summary>
        /// The minor version
        /// </summary>
        public readonly int Minor;

        /// <summary>
        /// Overridden to string method
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            if (IsVersionUnknown)
            {
                return "HTTP/Unknown";
            }
            else
            {
                return String.Format(CultureInfo.InvariantCulture, "HTTP/{0}.{1}", Major, Minor);
            }
        }
    }
}
