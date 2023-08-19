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
using System;
using System.Collections.Generic;
using System.IO;

namespace CANAPE.Net.Protocols.Parser
{
    /// <summary>
    /// HTTP parser implementation     
    /// </summary>
    public static class HttpParser
    {

        /// <summary>
        /// Check if has a header.
        /// </summary>
        /// <param name="headers">The list of headers</param>
        /// <param name="header">The header to find</param>
        /// <param name="values">Optional list of values to match</param>
        /// <returns>True if the header exists and contains at least one of these values</returns>
        public static bool HasHeader(this IEnumerable<HttpHeader> headers, string header, params string[] values)
        {
            bool ret = false;

            foreach (var pair in headers)
            {
                if (pair.Name.Equals(header, StringComparison.OrdinalIgnoreCase))
                {
                    if (values.Length == 0)
                    {
                        ret = true;
                    }
                    else
                    {
                        foreach (string value in values)
                        {
                            if (pair.Value.Equals(value, StringComparison.OrdinalIgnoreCase))
                            {
                                ret = true;
                                break;
                            }
                        }
                    }
                }
            }

            return ret;
        }

        /// <summary>
        /// Get a list of header values for a particular header
        /// </summary>
        /// <param name="headers">The list of headers</param>
        /// <param name="header">The header to find</param>
        /// <returns>A list of values</returns>
        public static IEnumerable<string> GetHeaderValues(this IEnumerable<HttpHeader> headers, string header)
        {
            foreach (var pair in headers)
            {
                if (pair.Name.Equals(header, StringComparison.OrdinalIgnoreCase))
                {
                    yield return pair.Value;
                }
            }
        }

        private static void CheckLineEnding(string line)
        {
            if (!line.EndsWith("\r\n"))
            {
                throw new HttpStreamParserException(Properties.Resources.HttpParser_StrictParsingInvalidLineEnd);
            }
        }

        private static IEnumerable<HttpHeader> ReadHeaders(DataReader reader, bool strictParsing, Logger logger)
        {
            while (true)
            {
                string line = reader.ReadLine();
                if (line.Length == 0)
                {
                    throw new EndOfStreamException();
                }

                if (strictParsing)
                {
                    CheckLineEnding(line);
                }

                // Technically this probably should be TrimEnd but for reasons of compatibilty probably best left
                line = line.Trim();

                if (line.Length == 0)
                {
                    break;
                }

                string[] values = line.Split(new char[] { ':' }, 2);
                string name = String.Empty;
                string value = String.Empty;

                if (strictParsing && values.Length != 2)
                {
                    throw new HttpStreamParserException(String.Format(Properties.Resources.HttpParser_InvalidHeaderException, line));
                }
                else
                {
                    if (values.Length > 0)
                    {
                        name = values[0];
                        if (values.Length > 1)
                        {
                            value = values[1];
                        }
                    }
                }

                yield return new HttpHeader(name.Trim(), value.Trim());
            }
        }

        /// <summary>
        /// Read a request header
        /// </summary>
        /// <param name="reader">The reader to use</param>
        /// <param name="strictParsing">Use strict parsing rules</param>
        /// <param name="logger">The logger to write errors to</param>            
        /// <exception cref="EndOfStreamException">Thrown when stream ends</exception>
        /// <returns>The request header object</returns>
        public static HttpRequestHeader ReadRequestHeader(DataReader reader, bool strictParsing, Logger logger)
        {
            return ReadRequestHeader(reader, strictParsing, logger, null);
        }

        /// <summary>
        /// Read a request header
        /// </summary>
        /// <param name="reader">The reader to use</param>
        /// <param name="strictParsing">Use strict parsing rules</param>
        /// <param name="logger">The logger to write errors to</param>    
        /// <param name="prefix">Some prefix characters, if null then just reads whole line</param>
        /// <exception cref="EndOfStreamException">Thrown when stream ends</exception>
        /// <returns>The request header object</returns>
        public static HttpRequestHeader ReadRequestHeader(DataReader reader, bool strictParsing, Logger logger, char[] prefix)
        {
            string header;

            if (prefix != null)
            {
                header = new string(prefix) + reader.ReadLine();
            }
            else
            {
                header = reader.ReadLine();
            }

            if (header.Length == 0)
            {
                throw new EndOfStreamException();
            }

            if (strictParsing)
            {
                CheckLineEnding(header);
            }

            // Let us default to version unknown
            HttpVersion ver = HttpVersion.VersionUnknown;
            List<HttpHeader> headers = new List<HttpHeader>();

            string[] values = header.Trim().Split(new char[] { ' ' }, 3);
            if (values.Length < 2)
            {
                throw new HttpStreamParserException(String.Format(Properties.Resources.HttpParser_RequestHeaderInvalid, header));
            }

            if (values.Length > 2)
            {
                if (!HttpVersion.TryParse(values[2], out ver))
                {
                    throw new HttpStreamParserException(Properties.Resources.HttpParser_InvalidHttpVersionString);
                }

                headers.AddRange(ReadHeaders(reader, strictParsing, logger));
            }

            return new HttpRequestHeader(reader, headers, values[0], values[1], ver);
        }

        /// <summary>
        /// Read the response header
        /// </summary>
        /// <param name="reader">The data reader to read from</param>        
        /// <param name="strictParsing">Use strict parsing rules</param>
        /// <param name="logger">The logger to write errors to</param>
        /// <exception cref="EndOfStreamException">Thrown when stream ends</exception>
        /// <returns>The http response header</returns>
        public static HttpResponseHeader ReadResponseHeader(DataReader reader, bool strictParsing, Logger logger)
        {
            // Read just first 4 chars
            string header = reader.ReadLine(BinaryEncoding.Instance, TextLineEnding.LineFeed, 4, true);
            if (strictParsing)
            {
                CheckLineEnding(header);
            }

            if (header.Equals("http", StringComparison.OrdinalIgnoreCase))
            {
                // Read to end of line
                header = header + reader.ReadLine();

                HttpVersion ver = new HttpVersion(1, 0);
                string[] values = header.Trim().Split(new char[] { ' ' }, 3);

                if (values.Length < 2)
                {
                    throw new HttpStreamParserException(String.Format(Properties.Resources.HttpParser_ResponseHeaderInvalid, header));
                }

                if (!HttpVersion.TryParse(values[0], out ver))
                {
                    throw new HttpStreamParserException(Properties.Resources.HttpParser_InvalidHttpVersionString);
                }

                int responseCode;

                if (!int.TryParse(values[1], out responseCode))
                {
                    throw new HttpStreamParserException(Properties.Resources.HttpParser_InvalidHttpResponseCode);
                }

                return new HttpResponseHeader(reader, ReadHeaders(reader, strictParsing, logger),
                    responseCode, values.Length > 2 ? values[2] : String.Empty, ver);
            }
            else
            {
                // Case where server probably responded with simple response even when we sent a full one
                return new HttpResponseHeader(reader, header);
            }
        }

        internal static long GetContentLength(IEnumerable<HttpHeader> headers)
        {
            long ret = 0;

            foreach (var pair in headers)
            {
                if (pair.Name.Equals("content-length", StringComparison.OrdinalIgnoreCase))
                {
                    if (!long.TryParse(pair.Value, out ret))
                    {
                        throw new HttpStreamParserException(String.Format(Properties.Resources.HttpParser_InvalidContentLength, pair.Value));
                    }
                }
            }

            return ret;
        }

        internal static bool IsChunkedEncoding(IEnumerable<HttpHeader> headers)
        {
            foreach (var pair in headers)
            {
                if (pair.Name.Equals("transfer-encoding", StringComparison.OrdinalIgnoreCase)
                    && pair.Value.Equals("chunked", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
