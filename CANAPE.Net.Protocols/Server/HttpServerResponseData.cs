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
using CANAPE.Utils;
using System.Collections.Generic;

namespace CANAPE.Net.Protocols.Server
{
    /// <summary>
    /// Response data for HTTP server implementation
    /// </summary>
    public class HttpServerResponseData
    {
        /// <summary>
        /// Response code
        /// </summary>
        public int ResponseCode { get; set; }

        /// <summary>
        /// Response message
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        /// Response body
        /// </summary>
        public byte[] Body { get; set; }

        /// <summary>
        /// Response body as a binary string
        /// </summary>
        public string BodyString
        {
            get { return BinaryEncoding.Instance.GetString(Body); }
            set
            {
                if (value == null)
                {
                    Body = new byte[0];
                }
                else
                {
                    Body = BinaryEncoding.Instance.GetBytes(value);
                }
            }
        }

        /// <summary>
        /// Response headers
        /// </summary>
        public Dictionary<string, string> Headers { get; private set; }

        /// <summary>
        /// Close after sending
        /// </summary>
        public bool CloseAfterSending { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        public HttpServerResponseData()
            : this(new byte[0], null)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="headers">Dictionary of headers</param>
        public HttpServerResponseData(IDictionary<string, string> headers)
            : this(new byte[0], headers)
        {
        }

        /// <summary>
        /// Constructor from a body
        /// </summary>
        /// <param name="body">The body data</param>
        /// <param name="headers">Dictionary of headers</param>
        public HttpServerResponseData(byte[] body, IDictionary<string, string> headers)
        {
            ResponseCode = 200;
            if (headers != null)
            {
                Headers = new Dictionary<string, string>(headers);
            }
            else
            {
                Headers = new Dictionary<string, string>();
            }
            Body = body;
        }

        /// <summary>
        /// Constructor from a body
        /// </summary>
        /// <param name="body">The body data</param>        
        public HttpServerResponseData(byte[] body)
            : this(body, null)
        {
        }

        /// <summary>
        /// Constructor from a binary string body
        /// </summary>
        /// <param name="body">The </param>
        /// <param name="headers">Dictionary of headers</param>
        public HttpServerResponseData(string body, IDictionary<string, string> headers)
            : this(BinaryEncoding.Instance.GetBytes(body), headers)
        {
        }

        /// <summary>
        /// Constructor from a binary string body
        /// </summary>
        /// <param name="body">The </param>
        public HttpServerResponseData(string body)
            : this(BinaryEncoding.Instance.GetBytes(body), null)
        {
        }
    }
}
