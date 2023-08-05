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
using CANAPE.Utils;
using System;
using System.Text.RegularExpressions;

namespace CANAPE.Net.Layers
{
    /// <summary>
    /// Match mode for entry
    /// </summary>
    public enum MatchMode
    {
        /// <summary>
        /// None
        /// </summary>
        None,
        /// <summary>
        /// Equal match
        /// </summary>
        Equal,
        /// <summary>
        /// Simple glob match
        /// </summary>
        Glob,
        /// <summary>
        /// Regex match
        /// </summary>
        Regex,
    }

    /// <summary>
    /// Entry for a HTTP match
    /// </summary>
    public class HttpMatchEntry
    {
        private string _match;
        private MatchMode _mode;
        private bool _ignoreCase;

        /// <summary>
        /// The match string
        /// </summary>
        public string Match
        {
            get { return _match; }
            set
            {
                _match = value ?? String.Empty;
            }
        }

        /// <summary>
        /// The mode of the match
        /// </summary>
        public MatchMode Mode
        {
            get { return _mode; }
            set { _mode = value; }
        }

        /// <summary>
        /// Whether case should be ignored
        /// </summary>
        public bool IgnoreCase
        {
            get { return _ignoreCase; }
            set { _ignoreCase = value; }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="match">Match string</param>
        /// <param name="mode">Match mode</param>
        public HttpMatchEntry(string match, MatchMode mode)
        {
            _match = match;
            Mode = mode;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public HttpMatchEntry()
            : this(String.Empty, MatchMode.None)
        {
        }

        /// <summary>
        /// Overridden ToString
        /// </summary>
        /// <returns>The string</returns>
        public override string ToString()
        {
            return String.Format("Match: {0} Mode: {1}", Match, Mode);
        }

        /// <summary>
        /// Checks for a match
        /// </summary>
        /// <param name="value">The string to match against</param>
        /// <returns>True if a match</returns>
        public bool IsMatch(string value)
        {
            switch (Mode)
            {
                case MatchMode.Glob:
                    return GeneralUtils.GlobToRegex(_match, IgnoreCase).IsMatch(value);
                case MatchMode.Regex:
                    return new Regex(_match, IgnoreCase ? RegexOptions.IgnoreCase : RegexOptions.None).IsMatch(value);
                case MatchMode.Equal:
                    return value.Equals(_match, IgnoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
                default:
                    return true;
            }
        }
    }

    /// <summary>
    /// Entry for a single HTTP configuration
    /// </summary>
    public class HttpLayerConfigEntry
    {
        /// <summary>
        /// Matcher for a path
        /// </summary>
        public HttpMatchEntry PathMatch { get; set; }

        /// <summary>
        /// Matcher for a method
        /// </summary>
        public HttpMatchEntry MethodMatch { get; set; }

        /// <summary>
        /// Match for content-type
        /// </summary>
        public HttpMatchEntry ContentTypeMatch { get; set; }

        /// <summary>
        /// If true request body will be streamed rather than buffered up
        /// </summary>
        public bool RequestStreamBody { get; set; }

        /// <summary>
        /// If true response body will be streamed rather than buffered up
        /// </summary>
        public bool ResponseStreamBody { get; set; }

        /// <summary>
        /// Convert HTTP/1.1 content-length format response to chunked encoding (for easier manipulation)
        /// Only applicable if StreamBody has been set, otherwise the entire body is buffered anyway
        /// </summary>
        public bool ConvertToChunked { get; set; }

        /// <summary>
        /// Does this entry match the request
        /// </summary>
        /// <param name="request">The request</param>
        /// <returns>True if it matches</returns>
        public bool IsMatch(HttpRequestHeader request)
        {
            bool ret = true;

            if (request != null)
            {
                if (!PathMatch.IsMatch(request.Path))
                {
                    ret = false;
                }

                if (MethodMatch.IsMatch(request.Method))
                {
                    ret = false;
                }
            }

            return ret;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="request"></param>
        /// <param name="response"></param>
        /// <returns></returns>
        public bool IsMatch(HttpRequestHeader request, HttpResponseHeader response)
        {

            if (IsMatch(request))
            {
                foreach (var pair in response.Headers)
                {
                    if (pair.Name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                    {
                        return ContentTypeMatch.IsMatch(pair.Value);
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public HttpLayerConfigEntry()
        {
            PathMatch = new HttpMatchEntry("*", MatchMode.Glob);
            MethodMatch = new HttpMatchEntry("*", MatchMode.None);
            ContentTypeMatch = new HttpMatchEntry("*", MatchMode.None);
        }

        /// <summary>
        /// Overridden ToString
        /// </summary>
        /// <returns>The string</returns>
        public override string ToString()
        {
            return String.Format("Path: {0} Method: {1} ContentType: {2}", PathMatch, MethodMatch, ContentTypeMatch);
        }
    }
}
