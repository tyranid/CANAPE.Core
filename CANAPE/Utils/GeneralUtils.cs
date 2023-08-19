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
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace CANAPE.Utils
{
    /// <summary>
    /// Public static class containing some general helpful utility functions
    /// </summary>
    public static class GeneralUtils
    {
        private static Regex _formatRegex = new Regex("\\$[a-zA-Z_/.*][a-zA-Z0-9_/.*]*");

        /// <summary>
        /// Generate a MD5 hex string from a byte array
        /// </summary>
        /// <param name="data">The data to hash</param>
        /// <returns>The MD5 hex string</returns>
        public static string GenerateMd5String(byte[] data)
        {
            byte[] hash = MD5.Create().ComputeHash(data);
            StringBuilder builder = new StringBuilder();

            foreach (byte b in hash)
            {
                builder.AppendFormat(CultureInfo.InvariantCulture, "{0:X02}", b);
            }

            return builder.ToString();
        }

        /// <summary>
        /// Create a string from a byte array like python does
        /// </summary>
        /// <param name="data">The data to convert</param>
        /// <returns>The converted string, null if data was null</returns>
        public static string MakeByteString(byte[] data)
        {
            if (data != null)
            {
                return new BinaryEncoding().GetString(data);
            }

            return null;
        }

        /// <summary>
        /// Make a byte array from a string like python
        /// </summary>
        /// <param name="s">The string to convert (note any char values > 255 will be masked)</param>
        /// <returns>The byte array, null if s was null</returns>
        public static byte[] MakeByteArray(string s)
        {
            if (s != null)
            {
                return new BinaryEncoding().GetBytes(s);
            }

            return null;
        }

        /// <summary>
        /// Read a line of data from a stream, reads up to a NL
        /// </summary>
        /// <param name="stm">The stream to read from</param>
        /// <returns>The line</returns>
        /// <exception cref="System.IO.EndOfStreamException">Throw when no more data availeble</exception>
        public static string ReadLine(Stream stm)
        {
            List<byte> reqBytes = new List<byte>();
            int ch = 0;

            while ((ch = stm.ReadByte()) >= 0)
            {
                reqBytes.Add((byte)ch);
                if (ch == 10)
                {
                    break;
                }
            }

            if (reqBytes.Count == 0)
            {
                throw new EndOfStreamException(Properties.Resources.ReadLine_CountNotReadFromStream);
            }

            return MakeByteString(reqBytes.ToArray());
        }

        /// <summary>
        /// Create a printable escaped string, converts control characters to \xXX
        /// </summary>
        /// <param name="str">The string to escape</param>
        /// <returns>The escaped string</returns>
        public static string EscapeString(string str)
        {
            StringBuilder builder = new StringBuilder();

            foreach (char c in str)
            {
                if (c < 32)
                {
                    builder.AppendFormat(@"\x{0:X02}", (int)c);
                }
                else
                {
                    builder.Append(c);
                }
            }

            return builder.ToString();
        }

        /// <summary>
        /// Create a printable escaped string, converts control characters to \xXX from a byte array
        /// </summary>
        /// <param name="bytes">The bytes to escape</param>
        /// <returns>The escaped string</returns>
        public static string EscapeBytes(byte[] bytes)
        {
            return EscapeString(BinaryEncoding.Instance.GetString(bytes));
        }

        /// <summary>
        /// Swap bytes if necessary to get the correct endian
        /// </summary>
        /// <param name="arr">The bytes to swap</param>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns></returns>
        public static byte[] SwapBytes(byte[] arr, bool littleEndian)
        {
            if ((littleEndian && !BitConverter.IsLittleEndian) || (!littleEndian && BitConverter.IsLittleEndian))
            {
                return arr.Reverse().ToArray();
            }

            return arr;
        }

        /// <summary>
        /// Convert a basic Glob to a regular expression, ignoring case
        /// </summary>
        /// <param name="glob">The glob string</param>        
        /// <returns>The regular expression</returns>
        public static Regex GlobToRegex(string glob)
        {
            return GlobToRegex(glob, true);
        }

        /// <summary>
        /// Convert a basic Glob to a regular expression
        /// </summary>
        /// <param name="glob">The glob string</param>
        /// <param name="ignoreCase">Indicates that match should ignore case</param>
        /// <returns>The regular expression</returns>
        public static Regex GlobToRegex(string glob, bool ignoreCase)
        {
            StringBuilder builder = new StringBuilder();

            builder.Append("^");

            foreach (char ch in glob)
            {
                if (ch == '*')
                {
                    builder.Append(".*");
                }
                else if (ch == '?')
                {
                    builder.Append(".");
                }
                else
                {
                    builder.Append(Regex.Escape(new String(ch, 1)));
                }
            }

            builder.Append("$");

            return new Regex(builder.ToString(), ignoreCase ? RegexOptions.IgnoreCase : RegexOptions.None);
        }

        /// <summary>
        /// Read out a fixed number of bytes or throw and EndOfStreamException
        /// </summary>
        /// <param name="stm">The stream</param>
        /// <param name="totalLen">The length to read</param>
        /// <exception cref="EndOfStreamException"></exception>
        /// <returns>A byte array containing the data</returns>
        public static byte[] ReadBytes(Stream stm, int totalLen)
        {
            int len = 0;
            byte[] ret = new byte[totalLen];

            while (len < totalLen)
            {
                int read = stm.Read(ret, len, totalLen - len);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }
                len += read;
            }

            return ret;
        }

        /// <summary>
        /// Convert hex data to binary
        /// </summary>
        /// <param name="hex">The hex string to convert</param>
        /// <returns>The byte array</returns>
        public static byte[] HexToBinary(string hex)
        {
            return HexToBinary(hex, true);
        }

        /// <summary>
        /// Convert hex data to binary
        /// </summary>
        /// <param name="hex">The hex string to convert</param>
        /// <param name="filter">Whether to filter out hyphens</param>
        /// <returns>The byte array</returns>
        public static byte[] HexToBinary(string hex, bool filter)
        {
            string values = filter ? hex.Replace(" ", "") : hex;
            List<byte> ret = new List<byte>();

            if ((values.Length % 2) != 0)
            {
                throw new ArgumentException(Properties.Resources.GeneralUtils_InvalidHexStringLength);
            }

            for (int i = 0; i < values.Length; i += 2)
            {
                byte val;

                if (!byte.TryParse(values.Substring(i, 2), NumberStyles.HexNumber, null, out val))
                {
                    throw new ArgumentException(Properties.Resources.GeneralUtils_InvalidHexString);
                }

                ret.Add(val);
            }

            return ret.ToArray();
        }

        /// <summary>
        /// Return a version string for the application.
        /// </summary>
        /// <returns>The version string</returns>
        public static string GetVersionString()
        {
            return String.Format("v1.0.0");
        }

        /// <summary>
        /// Make a meta name which is private to a UUID
        /// </summary>
        /// <param name="uuid">The UUID</param>
        /// <param name="name">The name</param>
        /// <returns>The private name</returns>
        public static string MakePrivateMetaName(Guid uuid, string name)
        {
            return String.Format(CultureInfo.InvariantCulture, "{0}_{1}", uuid, name);
        }

        /// <summary>
        /// Converts a datetime to unix time
        /// </summary>
        /// <param name="time">The datetime structure</param>
        /// <exception cref="ArgumentException">If unix time would be invalid</exception>
        /// <returns>Unix time</returns>
        public static int ToUnixTime(DateTime time)
        {
            DateTime epoc = new DateTime(1970, 1, 1);
            DateTime maxTime = epoc.AddSeconds(int.MaxValue);

            if ((epoc.CompareTo(time) < 0) || (time.CompareTo(maxTime) >= 0))
            {
                throw new ArgumentException(String.Format(Properties.Resources.ToUnixTime_CannotConvert, time));
            }

            return (int)time.Subtract(epoc).TotalSeconds;
        }

        /// <summary>
        /// Converts a unix time to a datetime
        /// </summary>
        /// <param name="time">The number of seconds since 1/1/1970</param>
        /// <returns></returns>
        public static DateTime FromUnixTime(int time)
        {
            return new DateTime(1970, 1, 1).AddSeconds(time);
        }

        /// <summary>
        /// Converts encoding to an encoding object
        /// </summary>
        /// <param name="encoding">The encoding type</param>
        /// <returns>The encoding</returns>
        public static Encoding GetEncodingFromType(BinaryStringEncoding encoding)
        {
            Encoding ret;

            switch (encoding)
            {
                case BinaryStringEncoding.ASCII:
                    ret = new BinaryEncoding();
                    break;
                case BinaryStringEncoding.UTF16_BE:
                    ret = new UnicodeEncoding(true, false);
                    break;
                case BinaryStringEncoding.UTF16_LE:
                    ret = new UnicodeEncoding(false, false);
                    break;
                case BinaryStringEncoding.UTF32_BE:
                    ret = new UTF32Encoding(true, false);
                    break;
                case BinaryStringEncoding.UTF32_LE:
                    ret = new UTF32Encoding(false, false);
                    break;
                case BinaryStringEncoding.UTF8:
                    ret = new UTF8Encoding();
                    break;
                case BinaryStringEncoding.UTF7:
                    ret = new UTF7Encoding();
                    break;
                case BinaryStringEncoding.EBCDIC_US:
                    ret = Encoding.GetEncoding(37);
                    break;
                case BinaryStringEncoding.Latin1:
                    ret = Encoding.GetEncoding(28591);
                    break;
                case BinaryStringEncoding.ShiftJIS:
                    ret = Encoding.GetEncoding(932);
                    break;
                default:
                    ret = Encoding.GetEncoding((int)encoding);
                    break;
            }

            return ret;
        }

        /// <summary>
        /// Match two byte arrays
        /// </summary>
        /// <param name="data">The data to match</param>
        /// <param name="pos">The position in the data array</param>
        /// <param name="match">The match array</param>
        /// <returns>True if all bytes match</returns>
        public static bool MatchArray(byte[] data, int pos, byte[] match)
        {
            bool matched = true;

            if ((data.Length - pos) >= match.Length)
            {
                for (int i = 0; i < match.Length; ++i)
                {
                    if (data[pos + i] != match[i])
                    {
                        matched = false;
                        break;
                    }
                }
            }
            else
            {
                matched = false;
            }

            return matched;
        }

        /// <summary>
        /// Determines if a character is a hex character
        /// </summary>
        /// <param name="c">The character to test</param>
        /// <returns>True if it is hex</returns>
        public static bool IsHex(char c)
        {
            char lowerCase = Char.ToLowerInvariant(c);

            return (Char.IsDigit(c) || ((lowerCase >= 'a') && (lowerCase <= 'f')));
        }

        /// <summary>
        /// Method to sanitize a string to a valid filename
        /// </summary>
        /// <param name="name">The name to sanitize</param>
        /// <param name="replaceChar">The character to replace invalid characters with</param>
        /// <returns>The sanitized string</returns>
        public static string SanitizeFilename(string name, char replaceChar)
        {
            StringBuilder builder = new StringBuilder();
            char[] invalidPathChars = Path.GetInvalidPathChars();

            foreach (char c in name)
            {
                if ((c != ':') && !invalidPathChars.Contains(c))
                {
                    builder.Append(c);
                }
                else
                {
                    builder.Append(replaceChar);
                }
            }

            return builder.ToString();
        }

        /// <summary>
        /// Decode a C# style escaped string
        /// </summary>
        /// <param name="s">The string to decode</param>
        /// <returns>The decoded string</returns>
        public static string DecodeEscapedString(string s)
        {
            if ((s.Length == 0) || !s.Contains('\\'))
            {
                return s;
            }
            else
            {
                StringBuilder builder = new StringBuilder(s);

                int pos = 0;

                while (pos < builder.Length)
                {
                    if (builder[pos] == '\\')
                    {
                        int charsLeft = builder.Length - pos - 1;

                        if (charsLeft > 0)
                        {
                            char val = '\0';

                            builder.Remove(pos, 1);

                            switch (builder[pos])
                            {
                                case 'n':
                                    val = '\n';
                                    break;
                                case 't':
                                    val = '\t';
                                    break;
                                case 'r':
                                    val = '\r';
                                    break;
                                case '0':
                                    val = '\0';
                                    break;
                                case '\\':
                                    val = '\\';
                                    break;
                                default:
                                    throw new FormatException(String.Format(Properties.Resources.GeneralUtils_DecodeEscapedInvalidEscape, builder[pos]));
                            }

                            builder[pos] = val;
                        }
                        else
                        {
                            throw new FormatException(Properties.Resources.GeneralUtils_DecodeEscapedStringTrailingSlash);
                        }
                    }

                    pos++;
                }

                return builder.ToString();
            }
        }

        /// <summary>
        /// Compare two byte arrays
        /// </summary>
        /// <param name="x">Byte array x</param>
        /// <param name="y">Byte array y</param>
        /// <returns>True if they are equal</returns>
        public static bool CompareBytes(byte[] x, byte[] y)
        {
            if (x.Length == y.Length)
            {
                bool ret = true;

                for (int i = 0; i < x.Length; ++i)
                {
                    if (x[i] != y[i])
                    {
                        ret = false;
                        break;
                    }
                }

                return ret;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Get the hash code of a byte array
        /// </summary>
        /// <param name="ba">The array of bytes</param>
        /// <returns>The hash code</returns>
        public static int GetBytesHashCode(byte[] ba)
        {
            int hash = 27;

            foreach (byte b in ba)
            {
                hash = (hash * 13) + b;
            }

            return hash;
        }

        /// <summary>
        /// Writes the packets to file.
        /// </summary>
        /// <param name="filename">The filename</param>
        /// <param name="packets">The packets</param>
        public static void WritePacketsToFile(string filename, IEnumerable<LogPacket> packets)
        {
            using (var stream = File.OpenWrite(filename))
            {
                foreach (var packet in packets)
                {
                    packet.WriteToStream(stream);
                }
            }
        }

        /// <summary>
        /// Reads the packets from file.
        /// </summary>
        /// <returns>The packets from file.</returns>
        /// <param name="filename">The filename</param>
        public static IEnumerable<LogPacket> ReadPacketsFromFile(string filename)
        {
            using (var stream = File.OpenRead(filename))
            {
                List<LogPacket> packets = new List<LogPacket>();
                try
                {
                    while (true)
                    {
                        packets.Add(LogPacket.ReadFromStream(stream));
                    }
                }
                catch (EndOfStreamException)
                {
                }
                return packets;
            }
        }
    }
}
