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
using CANAPE.DataFrames;
using CANAPE.Utils;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CANAPE.Net.Protocols.Parser
{
    /// <summary>
    /// Class which represents a basic chunk of HTTP data
    /// </summary>
    public abstract class HttpDataChunk<T> : IDataValue<T>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="headers">List of headers</param>
        /// <param name="version">The HTTP version</param>
        protected HttpDataChunk(IEnumerable<HttpHeader> headers, HttpVersion version)
        {
            Headers = headers.ToArray();
            Version = version;
            Body = new byte[0];
        }

        /// <summary>
        /// Constructor
        /// </summary>
        protected HttpDataChunk()
            : this(new HttpHeader[0], HttpVersion.VersionUnknown)
        {
        }

        /// <summary>
        /// Called when writing the header
        /// </summary>
        /// <returns>The string of data for the header</returns>
        protected abstract string OnWriteHeader();

        /// <summary>
        /// Method to determine if a connection should be closed after body is sent
        /// </summary>
        /// <returns>Defaults to false</returns>
        public virtual bool CloseAfterBody()
        {
            return false;
        }

        /// <summary>
        /// Method to determine if this response/request can send a body at all (influenced by the content length)
        /// </summary>
        /// <returns></returns>
        protected abstract bool CanSendBody();

        /// <summary>
        /// The headers associated with this chunk
        /// </summary>
        public HttpHeader[] Headers { get; set; }

        /// <summary>
        /// Indicates the version of HTTP to use
        /// </summary>
        public HttpVersion Version { get; set; }

        /// <summary>
        /// The data associated with this chunk
        /// </summary>
        public byte[] Body { get; set; }

        /// <summary>
        /// Get the body as a string
        /// </summary>
        public string GetBodyString()
        {
            return BinaryEncoding.Instance.GetString(Body ?? new byte[0]);
        }

        /// <summary>
        /// Set the body as a string
        /// </summary>
        /// <param name="body">The body string</param>
        public void SetBodyString(string body)
        {
            Body = BinaryEncoding.Instance.GetBytes(body ?? String.Empty);
        }

        /// <summary>
        /// The number of the chunk, starting from 0
        /// </summary>
        public int ChunkNumber { get; set; }

        /// <summary>
        /// Indicates if this chunk is the final one (buffered packets set ChunkNumber to 0 and FinalChunk to true)
        /// </summary>
        public bool FinalChunk { get; set; }

        /// <summary>
        /// Indicates if this chunk is based on chunked encoding
        /// </summary>
        public bool ChunkedEncoding { get; set; }

        /// <summary>
        /// String representing any chunk extension
        /// </summary>
        public string ChunkExtension { get; set; }

        /// <summary>
        /// Add a header to the chunk
        /// </summary>
        /// <param name="header">The header name</param>
        /// <param name="value">The value of the header</param>
        public void AddHeader(string header, string value)
        {
            List<HttpHeader> newHeaders = new List<HttpHeader>();

            if (Headers != null)
            {
                newHeaders.AddRange(Headers);
            }

            newHeaders.Add(new HttpHeader(header, value));

            Headers = newHeaders.ToArray();
        }

        /// <summary>
        /// Remove a header from the chunk
        /// </summary>
        /// <param name="header">The header to remove</param>
        public void RemoveHeader(string header)
        {
            if (Headers != null)
            {
                List<HttpHeader> newHeaders = new List<HttpHeader>();
                foreach (HttpHeader value in Headers)
                {
                    if (!value.Name.Equals(header, StringComparison.OrdinalIgnoreCase))
                    {
                        newHeaders.Add(value);
                    }
                }

                Headers = newHeaders.ToArray();
            }
        }

        private static void WriteLine(DataWriter writer, string line)
        {
            writer.WriteLine(line, TextLineEnding.CarriageReturnLineFeed);
        }

        /// <summary>
        /// Called to determine if content length should be filtered
        /// </summary>
        /// <returns></returns>
        protected virtual bool FilterContentLength()
        {
            return true;
        }

        private bool FilterHeader(string name, string value)
        {
            bool filterContentLength = FilterContentLength();

            // Filter out content-length from headers if this is the final chunk (i.e. only chunk) or we couldn't send a body anyway            
            if (filterContentLength && name.Equals("content-length", StringComparison.OrdinalIgnoreCase))
            {
                // Don't send if couldn't send body anyway or this is the only chunk 
                // where we will ensure it is set appropriately for the Body
                if (!CanSendBody() || FinalChunk)
                {
                    return true;
                }
            }

            return false;
        }

        private void WriteHeaders(DataWriter writer)
        {
            string writeHeader = OnWriteHeader();

            // null indicates that a response has no headers
            if (writeHeader != null)
            {
                WriteLine(writer, writeHeader);

                foreach (HttpHeader pair in Headers)
                {
                    if (!FilterHeader(pair.Name, pair.Value))
                    {
                        WriteLine(writer, String.Format("{0}: {1}", pair.Name, pair.Value));
                    }
                }

                // If this is the one and only chunk with content-length then send new length header
                if (!ChunkedEncoding && FinalChunk && CanSendBody())
                {
                    WriteLine(writer, String.Format("Content-Length: {0}", GetBody().Length));
                }

                WriteLine(writer, String.Empty);
            }
        }

        private byte[] GetBody()
        {
            if (Body == null)
            {
                return new byte[0];
            }
            else
            {
                return Body;
            }
        }

        private void WriteBody(DataWriter writer)
        {
            byte[] body = GetBody();

            if (ChunkedEncoding)
            {
                string chunkLen = String.Format("{0:X}", body.Length);

                if (!String.IsNullOrEmpty(ChunkExtension))
                {
                    chunkLen += ";" + ChunkExtension;
                }

                WriteLine(writer, chunkLen);

                writer.WriteBytes(body);

                WriteLine(writer, String.Empty);

                if (FinalChunk && body.Length > 0)
                {
                    WriteLine(writer, "0");
                    WriteLine(writer, String.Empty);
                }
            }
            else
            {
                writer.WriteBytes(Body);
            }
        }

        /// <summary>
        /// Write the check to a data writer
        /// </summary>
        /// <param name="writer">The writer to write to</param>        
        public void WriteChunk(DataWriter writer)
        {
            if (ChunkNumber == 0)
            {
                WriteHeaders(writer);
            }

            WriteBody(writer);
        }

        void IDataValue<T>.ToWriter(DataWriter writer)
        {
            WriteChunk(writer);
        }

        /// <summary>
        /// Clone this instance.
        /// </summary>
        /// <returns>The clone.</returns>
        public T Clone()
        {
            return (T)MemberwiseClone();
        }
    }
}
