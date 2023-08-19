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
using CANAPE.Net.Protocols.Parser;
using CANAPE.Net.Protocols.Server;
using CANAPE.Utils;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace CANAPE.NodeLibrary.Server
{
    /// <summary>
    /// Config for simple HTTP server
    /// </summary>
    public class HttpDataServerConfig
    {
        /// <summary>
        /// A HTTP path to match against
        /// </summary>

        public string HttpPath { get; set; }

        /// <summary>
        /// Gets or sets the valid response data.
        /// </summary>
        /// <value>The valid response data.</value>

        public byte[] ValidResponseData { get; set; }

        /// <summary>
        /// Gets or sets the not found response data.
        /// </summary>
        /// <value>The not found response data.</value>

        public byte[] NotFoundResponseData { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this <see cref="T:CANAPE.NodeLibrary.Server.HttpDataServerConfig"/>
        /// close after sending.
        /// </summary>
        /// <value><c>true</c> if close after sending; otherwise, <c>false</c>.</value>

        public bool CloseAfterSending { get; set; }

        /// <summary>
        /// Gets or sets the type of the content.
        /// </summary>
        /// <value>The type of the content.</value>

        public string ContentType { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.NodeLibrary.Server.HttpDataServerConfig"/> class.
        /// </summary>
        public HttpDataServerConfig()
        {
            HttpPath = "/*";
            ContentType = "text/html";
            ValidResponseData = new byte[0];
            NotFoundResponseData = new byte[0];
            CloseAfterSending = true;
        }
    }

    /// <summary>
    /// Http data server.
    /// </summary>
    public class HttpDataServer : BaseHttpDataServer<HttpDataServerConfig>
    {
        /// <summary>
        /// Handles the request.
        /// </summary>
        /// <returns>The request.</returns>
        /// <param name="method">Method.</param>
        /// <param name="path">Path.</param>
        /// <param name="body">Body.</param>
        /// <param name="headers">Headers.</param>
        /// <param name="version">Version.</param>
        /// <param name="logger">Logger.</param>
        protected override HttpServerResponseData HandleRequest(string method, string path, byte[] body,
            Dictionary<string, string> headers, HttpVersion version, Logger logger)
        {
            Regex pathRegex = GeneralUtils.GlobToRegex(Config.HttpPath);
            HttpServerResponseData data = new HttpServerResponseData();

            data.CloseAfterSending = Config.CloseAfterSending;

            if (pathRegex.IsMatch(path))
            {
                data.ResponseCode = 200;
                data.Message = "OK";
                if (Config.ValidResponseData != null)
                {
                    data.Body = Config.ValidResponseData;
                }
            }
            else
            {
                data.ResponseCode = 404;
                data.Message = "Not Found";
                if (Config.NotFoundResponseData != null)
                {
                    data.Body = Config.NotFoundResponseData;
                }
            }

            data.Headers["Content-Type"] = Config.ContentType ?? "text/html";

            return data;
        }

        /// <summary>
        /// Gets the description.
        /// </summary>
        /// <value>The description.</value>
        public override string Description
        {
            get { return "Simple HTTP Server"; }
        }
    }
}
