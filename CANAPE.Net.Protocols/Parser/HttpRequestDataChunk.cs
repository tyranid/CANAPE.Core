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

namespace CANAPE.Net.Protocols.Parser
{
    /// <summary>
    /// A data chunk for a request
    /// </summary>
    public sealed class HttpRequestDataChunk : HttpDataChunk<HttpRequestDataChunk>
    {
        internal HttpRequestDataChunk(HttpRequestHeader header)
            : base(header.Headers, header.Version)
        {
            Method = header.Method;
            Path = header.Path;
        }

        /// <summary>
        /// Public constructor
        /// </summary>
        public HttpRequestDataChunk()
        {
            Method = "GET";
            Path = "/";
        }

        /// <summary>
        /// Request method
        /// </summary>
        public string Method { get; set; }

        /// <summary>
        /// Request path
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// Convert to a HTTP header
        /// </summary>
        /// <returns></returns>
        public HttpRequestHeader ToHeader()
        {
            return new HttpRequestHeader(null, Headers, Method, Path, Version);
        }

        /// <summary>
        /// Called when writing the header
        /// </summary>
        /// <returns>The string of data for the header</returns>
        protected override string OnWriteHeader()
        {
            string ret = null;

            if ((Method != null) && (Path != null))
            {
                ret = String.Format(CultureInfo.InvariantCulture, "{0} {1}", Method, Path);
                if (!Version.IsVersionUnknown)
                {
                    ret = String.Format(CultureInfo.InvariantCulture, "{0} {1}", ret, Version);
                }
            }
            else
            {
                throw new HttpStreamParserException(Properties.Resources.HttpParser_MissingMethodAndPath);
            }

            return ret;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public override bool CloseAfterBody()
        {
            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        protected override bool CanSendBody()
        {
            // These methods cannot send a body
            if (Method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                || Method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }
    }
}
