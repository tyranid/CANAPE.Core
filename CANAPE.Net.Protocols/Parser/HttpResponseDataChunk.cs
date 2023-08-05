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
    /// Http response data chunk.
    /// </summary>
    public sealed class HttpResponseDataChunk : HttpDataChunk<HttpResponseDataChunk>
    {
        /// <summary>
        /// Gets or sets the response code.
        /// </summary>
        /// <value>The response code.</value>
        public int ResponseCode { get; set; }

        /// <summary>
        /// Gets or sets the message.
        /// </summary>
        /// <value>The message.</value>
        public string Message { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this
        /// <see cref="T:CANAPE.Net.Protocols.Parser.HttpResponseDataChunk"/> head response.
        /// </summary>
        /// <value><c>true</c> if head response; otherwise, <c>false</c>.</value>
        public bool HeadResponse { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this
        /// <see cref="T:CANAPE.Net.Protocols.Parser.HttpResponseDataChunk"/> connect response.
        /// </summary>
        /// <value><c>true</c> if connect response; otherwise, <c>false</c>.</value>
        public bool ConnectResponse { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.Net.Protocols.Parser.HttpResponseDataChunk"/> class.
        /// </summary>
        public HttpResponseDataChunk()
        {
        }

        internal HttpResponseDataChunk(HttpResponseHeader header) : base(header.Headers, header.Version)
        {
            ResponseCode = header.ResponseCode;
            Message = header.Message;
            HeadResponse = header.HeadRequest;
            ConnectResponse = header.ConnectRequest;
        }

        /// <summary>
        /// Ons the write header.
        /// </summary>
        /// <returns>The write header.</returns>
        protected override string OnWriteHeader()
        {
            string ret = null;

            if (!Version.IsVersionUnknown)
            {
                if (!String.IsNullOrWhiteSpace(Message))
                {
                    ret = String.Format(CultureInfo.InvariantCulture, "{0} {1} {2}", Version, ResponseCode, Message);
                }
                else
                {
                    ret = String.Format(CultureInfo.InvariantCulture, "{0} {1}", Version, ResponseCode);
                }
            }

            return ret;
        }

        /// <summary>
        /// Cans the send body.
        /// </summary>
        /// <returns><c>true</c>, if send body was caned, <c>false</c> otherwise.</returns>
        protected override bool CanSendBody()
        {
            if (HeadResponse || ConnectResponse || ResponseCode == 304 || (ResponseCode >= 100 && ResponseCode < 200))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Filters the length of the content.
        /// </summary>
        /// <returns><c>true</c>, if content length was filtered, <c>false</c> otherwise.</returns>
        protected override bool FilterContentLength()
        {
            return !HeadResponse && !ConnectResponse;
        }
    }
}
