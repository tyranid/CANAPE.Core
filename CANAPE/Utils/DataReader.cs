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
using CANAPE.DataAdapters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace CANAPE.Utils
{
    /// <summary>
    /// Class to enclose a standard stream
    /// and provide simple mechanisms to read and write arrays and 
    /// python compatible strings
    /// </summary>    
    public sealed class DataReader
    {
        const int CHUNK_LENGTH = 8192;

        bool _eof;
        CountedStream _stm;
        int _validBits;
        byte _currBits;

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="stm"></param>        
        public DataReader(Stream stm)
        {
            _stm = new CountedStream(stm);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="data">Byte data to read</param>
        public DataReader(byte[] data)
            : this(new MemoryStream(data))
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="adapter">A data adapter to wrap</param>
        public DataReader(IDataAdapter adapter)
            : this(new DataAdapterToStream(adapter))
        {
        }

        /// <summary>
        /// Read bytes waiting for all options and throwing options
        /// </summary>
        /// <param name="len">The length to read</param>
        /// <param name="waitForAll">Whether to wait for all the data to be read, if cannot read number of bytes throw an exception</param>
        /// <param name="throwOnEof">If true then throws at EOF during process, also if waitForAll if this is false it will return the final short read</param>
        /// <returns>An array of bytes, up to length depending on mode</returns>
        public byte[] ReadBytes(int len, bool waitForAll, bool throwOnEof)
        {
            List<byte> ret = new List<byte>();
            int currLen = 0;

            if (_eof)
            {
                throw new EndOfStreamException();
            }

            // Clear any current bit data
            _validBits = 0;

            while (currLen < len)
            {
                int nextLen = (len - currLen) > CHUNK_LENGTH ? CHUNK_LENGTH : (len - currLen);

                byte[] arr = new byte[nextLen];

                int readLen = _stm.Read(arr, 0, nextLen);

                if (readLen == 0)
                {
                    _eof = true;
                    break;
                }

                if (readLen < nextLen)
                {
                    Array.Resize<byte>(ref arr, readLen);
                }

                ret.AddRange(arr);

                currLen = ret.Count;

                // If not waiting for all then break here (even if currLen == len)
                if (!waitForAll)
                {
                    break;
                }
            }

            if (waitForAll)
            {
                if ((currLen != len) && throwOnEof)
                {
                    throw new EndOfStreamException(Properties.Resources.DataReader_ReadBytesEof);
                }
            }
            else
            {
                if (throwOnEof && (currLen == 0))
                {
                    throw new EndOfStreamException();
                }
            }

            return ret.ToArray();
        }

        /// <summary>
        /// Read bytes from the stream, up to a maximum of the length, and empty array indicates 
        /// end of stream
        /// </summary>
        /// <param name="len">The maximum length to read</param>
        /// <param name="waitForAll">Whether to wait for all the bytes to arrive</param>
        /// <exception cref="System.IO.EndOfStreamException">Throws exception if waitForAll is true but not all data could be read</exception>
        /// <returns>An array up to len bytes long</returns>
        public byte[] ReadBytes(int len, bool waitForAll)
        {
            return ReadBytes(len, waitForAll, true);
        }

        /// <summary>
        /// Read bytes from the stream, up to a maximum of the length, and empty array indicates 
        /// end of stream. Wait for all data to arrive
        /// </summary>
        /// <param name="len">The maximum length to read</param>        
        /// <returns>An array up to len bytes long, empty array on end of stream</returns>
        public byte[] ReadBytes(int len)
        {
            return ReadBytes(len, true);
        }

        /// <summary>
        /// Read all data till the end of the stream
        /// </summary>
        /// <returns>The bytes to the end of the stream</returns>
        public byte[] ReadToEnd()
        {
            List<byte> ret = new List<byte>();
            byte[] arr = null;

            do
            {
                arr = ReadBytes(CHUNK_LENGTH, false, false);

                if (arr.Length > 0)
                {
                    ret.AddRange(arr);
                }
            }
            while (arr.Length > 0);

            return ret.ToArray();
        }

        /// <summary>
        /// Read all data till end of the stream, or until chunksize is reached
        /// </summary>
        /// <param name="chunkSize">The size of the chunk to read</param>
        /// <returns>The data read</returns>
        public byte[] ReadToEnd(int chunkSize)
        {
            List<byte> ret = new List<byte>();
            byte[] arr = null;
            int currLength = chunkSize;

            while (currLength > 0)
            {
                arr = ReadBytes(currLength, false, false);

                if (arr.Length > 0)
                {
                    ret.AddRange(arr);
                    currLength -= arr.Length;
                }
                else
                {
                    break;
                }
            }

            return ret.ToArray();
        }

        /// <summary>
        /// Read to end of stream as a string
        /// </summary>
        /// <param name="encoding">The encoding to use</param>
        /// <returns>The string</returns>
        public string ReadToEnd(Encoding encoding)
        {
            return encoding.GetString(ReadToEnd());
        }

        private void ResetStreamTrail(byte[] data)
        {
            if (data.Length > 0)
            {
                // If this stream can seek then revert it back
                if (_stm.CanSeek)
                {
                    _stm.Position = _stm.Length - data.Length;
                }
                else
                {
                    _stm = new CountedStream(new MemoryStream(data));
                }

                _eof = false;
            }
        }

        /// <summary>
        /// Read almost to the end, leaving a trailing amount of bytes in the reader
        /// </summary>
        /// <remarks>Note this might change the reader's stream if it doesn't support seeking</remarks>        
        /// <param name="trail">The number of trailing characters or bytes</param>        
        /// <returns>The read bytes</returns>        
        public byte[] ReadToEndTrail(int trail)
        {
            byte[] ret = ReadToEnd();

            if (trail > 0)
            {
                byte[] t;

                if (ret.Length <= trail)
                {
                    t = ret;
                    ret = new byte[0];
                }
                else
                {
                    t = new byte[trail];
                    Array.Copy(ret, ret.Length - trail, t, 0, trail);
                    Array.Resize(ref ret, ret.Length - trail);
                }

                ResetStreamTrail(t);
            }

            return ret;
        }

        /// <summary>
        /// Read almost to the end, leaving a trailing amount of characters in the reader
        /// </summary>
        /// <remarks>Note this might change the reader's stream if it doesn't support seeking</remarks>
        /// <param name="encoding">The string encoding to use</param>
        /// <param name="trail">The number of trailing characters or bytes</param>        
        /// <returns>The read string</returns>
        public string ReadToEndTrail(Encoding encoding, int trail)
        {
            string s = ReadToEnd(encoding);

            if (trail > 0)
            {
                string t;

                if (s.Length <= trail)
                {
                    t = s;
                    s = String.Empty;
                }
                else
                {
                    t = s.Substring(s.Length - trail);
                    s = s.Substring(0, s.Length - trail);
                }

                ResetStreamTrail(encoding.GetBytes(t));
            }

            return s;
        }

        /// <summary>
        /// Read a character from the stream using a specified byte encoding
        /// </summary>
        /// <param name="encoding">The encoding</param>
        /// <exception cref="InvalidOperationException">Could not read a character from the stream</exception>
        /// <returns>The character read</returns>
        public char ReadChar(Encoding encoding)
        {
            if (encoding.IsSingleByte)
            {
                return encoding.GetChars(ReadBytes(1, true))[0];
            }
            else
            {
                byte[] data = new byte[encoding.GetMaxByteCount(1)];
                for (int i = 0; i < data.Length; ++i)
                {
                    data[i] = ReadByte();
                    if (encoding.GetCharCount(data, 0, i + 1) == 1)
                    {
                        return encoding.GetChars(data, 0, i + 1)[0];
                    }
                }
            }

            throw new InvalidOperationException(CANAPE.Properties.Resources.DataReader_ReadCharEof);
        }

        /// <summary>
        /// Read a character from the stream using a binary encoding
        /// </summary>
        /// <returns>The byte as a character</returns>
        public char ReadChar()
        {
            return (char)ReadByte();
        }

        /// <summary>
        /// Read a string from the stream using a specified encoding
        /// </summary>
        /// <param name="len">Maximum length to read (in chars)</param>
        /// <param name="waitForAll">Whether to wait for all the chars to arrive</param>
        /// <param name="encoding">The encoding to use</param>
        /// <returns>The read string</returns>
        public string ReadString(int len, bool waitForAll, Encoding encoding)
        {
            if (encoding.IsSingleByte)
            {
                // We can do it more simply for single byte encoded data
                return encoding.GetString(ReadBytes(len, waitForAll));
            }
            else
            {
                // We need to read it slowly
                StringBuilder builder = new StringBuilder();

                try
                {
                    for (int i = 0; i < len; ++i)
                    {
                        builder.Append(ReadChar(encoding));
                    }
                }
                catch (EndOfStreamException)
                {
                    if (waitForAll)
                    {
                        throw;
                    }
                }

                return builder.ToString();
            }
        }

        /// <summary>
        /// Read a string from the stream using a specified encoding
        /// </summary>
        /// <param name="len">Maximum length to read (in chars)</param>
        /// <param name="waitForAll">Whether to wait for all the chars to arrive</param>
        /// <returns>The read string</returns>
        public string ReadString(int len, bool waitForAll)
        {
            return ReadString(len, waitForAll, new BinaryEncoding());
        }

        /// <summary>
        /// Read a string from the stream. Wait for all data to arrive
        /// </summary>
        /// <param name="len">Maximum length to read</param>
        /// <returns>The python style string</returns>
        public string ReadString(int len)
        {
            return ReadString(len, true);
        }

        /// <summary>
        /// Read a string from the stream with a terminating character
        /// </summary>
        /// <param name="term">The terminating character</param>
        /// <exception cref="EndOfStreamException">Thrown if end of stream reached before reading terminator</exception>
        /// <returns>The string read from the stream (without the terminator)</returns>
        public string ReadTerminatedString(char term)
        {
            return ReadTerminatedString(BinaryEncoding.Instance, term);
        }

        /// <summary>
        /// Read a string from the stream with a terminating character
        /// </summary>
        /// <param name="encoding">The character encoding to use</param>
        /// <param name="term">The terminating character</param>
        /// <exception cref="EndOfStreamException">Thrown if end of stream reached before reading terminator</exception>
        /// <returns>The string read from the stream (without the terminator)</returns>
        public string ReadTerminatedString(Encoding encoding, char term)
        {
            StringBuilder builder = new StringBuilder();

            char ch = ReadChar(encoding);
            while (ch != term)
            {
                builder.Append(ch);
                ch = ReadChar(encoding);
            }

            return builder.ToString();
        }

        /// <summary>
        /// Read a NUL terminated string from the stream
        /// </summary>
        /// <param name="encoding">The character encoding to use</param>
        /// <exception cref="EndOfStreamException">Thrown if end of stream reached before reading terminator</exception>
        /// <returns>The nul terminated string (without the terminator)</returns>
        public string ReadNulTerminatedString(Encoding encoding)
        {
            return ReadTerminatedString(encoding, '\0');
        }

        /// <summary>
        /// Read a NUL terminated string from the stream with binary encoding
        /// </summary>
        /// <exception cref="EndOfStreamException">Thrown if end of stream reached before reading terminator</exception>
        /// <returns>The nul terminated string (without the terminator)</returns>
        public string ReadNulTerminatedString()
        {
            return ReadTerminatedString(BinaryEncoding.Instance, '\0');
        }

        /// <summary>
        /// Read a ASCII python compatible string from the stream with LF line ending
        /// </summary>
        /// <returns>The string, empty string on end of stream</returns>
        public string ReadLine()
        {
            return ReadLine(BinaryEncoding.Instance);
        }

        /// <summary>
        /// Read a ASCII python compatible string from the stream with a specified line ending
        /// </summary>
        /// <param name="lineEnding">The line ending</param>
        /// <returns>The string, empty string on end of stream</returns>
        public string ReadLine(TextLineEnding lineEnding)
        {
            return ReadLine(BinaryEncoding.Instance, lineEnding);
        }

        /// <summary>
        /// Read an encoded line of text from the stream, with LF line ending
        /// </summary>
        /// <param name="encoding">The text encoding to use</param>        
        /// <returns>The string, empty string on end of stream</returns>
        public string ReadLine(Encoding encoding)
        {
            return ReadLine(encoding, TextLineEnding.LineFeed);
        }

        /// <summary>
        /// Read an encoded line of text from the stream, with a specified line ending
        /// </summary>
        /// <param name="encoding">The text encoding to use</param>
        /// <param name="lineEnding">Specify the line ending required for the line</param>        
        /// <returns>The string, empty string on end of stream</returns>
        public string ReadLine(Encoding encoding, TextLineEnding lineEnding)
        {
            return ReadLine(encoding, lineEnding, 0, false);
        }

        /// <summary>
        /// Read an encoded line of text from the stream, with a specified line ending
        /// </summary>
        /// <param name="encoding">The text encoding to use</param>
        /// <param name="lineEnding">Specify the line ending required for the line</param>
        /// <param name="maxLength">Maximum length of a line, &lt;= 0 indicates to end of string</param>
        /// <param name="throwOnEof">If true throws EndOfStream on EoF otherwise returns an empty string</param>
        /// <returns>The string, empty string on end of stream</returns>
        public string ReadLine(Encoding encoding, TextLineEnding lineEnding, int maxLength, bool throwOnEof)
        {
            StringBuilder buf = new StringBuilder();
            bool hasCr = false;

            if (!_eof)
            {
                try
                {
                    while (true)
                    {
                        char currChar = ReadChar(encoding);
                        buf.Append(currChar);

                        if ((maxLength > 0) && (buf.Length == maxLength))
                        {
                            break;
                        }

                        if (currChar == '\n')
                        {
                            if (lineEnding == TextLineEnding.LineFeed)
                            {
                                break;
                            }
                            else if ((lineEnding == TextLineEnding.CarriageReturnLineFeed) && hasCr)
                            {
                                break;
                            }
                        }
                        else if (currChar == '\r')
                        {
                            if (lineEnding == TextLineEnding.CarriageReturn)
                            {
                                break;
                            }
                            else
                            {
                                hasCr = true;
                            }
                        }
                        else
                        {
                            hasCr = false;
                        }
                    }
                }
                catch (EndOfStreamException)
                {
                    if (buf.Length == 0 && throwOnEof)
                    {
                        // Rethrow if buffer was 0
                        throw;
                    }
                }
            }

            return buf.ToString();
        }

        /// <summary>
        /// Read a byte from the stream
        /// </summary>
        /// <exception cref="System.IO.EndOfStreamException">Throw on end of stream</exception>
        /// <returns>The byte read</returns>
        public byte ReadByte()
        {
            if (_eof)
            {
                throw new EndOfStreamException();
            }

            // Clear any current bit data
            _validBits = 0;

            int currByte = _stm.ReadByte();
            if (currByte < 0)
            {
                _eof = true;
                throw new EndOfStreamException();
            }

            return (byte)currByte;
        }

        /// <summary>
        /// Flush out any pending bits
        /// </summary>
        public void Flush()
        {
            _validBits = 0;
        }

        /// <summary>
        /// Read a 7 bit encoded integer from the stream
        /// </summary>
        /// <returns></returns>
        public ulong ReadInt7V()
        {
            ulong ret = 0;
            int bytePos = 0;

            while (true)
            {
                byte b = ReadByte();
                ret |= ((ulong)b & 0x7F) << (bytePos++ * 7);
                if ((b & 0x80) == 0)
                {
                    break;
                }
            }

            return ret;
        }

        /// <summary>
        /// Read a signed byte from the stream
        /// </summary>
        /// <returns></returns>
        public sbyte ReadSByte()
        {
            byte[] bs = new[] { ReadByte() };

            return ((sbyte[])(Array)bs)[0];
        }

        /// <summary>
        /// Read a short from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <exception cref="System.IO.EndOfStreamException">Throw on end of stream</exception>
        /// <returns>The read value</returns>
        public short ReadInt16(bool littleEndian)
        {
            byte[] data = ReadBytes(2);

            return BitConverter.ToInt16(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a big endian short from the stream
        /// </summary>
        /// <exception cref="System.IO.EndOfStreamException">Throw on end of stream</exception>
        /// <returns>The read value</returns>
        public short ReadInt16()
        {
            return ReadInt16(false);
        }

        /// <summary>
        /// Read an unsigned short from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns>The read value</returns>
        public ushort ReadUInt16(bool littleEndian)
        {
            byte[] data = ReadBytes(2);

            return BitConverter.ToUInt16(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a big endian unsigned short from the stream
        /// </summary>        
        /// <returns>The read value</returns>
        public ushort ReadUInt16()
        {
            return ReadUInt16(false);
        }

        /// <summary>
        /// Read an integer from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns>The read value</returns>
        public int ReadInt32(bool littleEndian)
        {
            byte[] data = ReadBytes(4);

            return BitConverter.ToInt32(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a big endian integer from the stream
        /// </summary>
        /// <returns>The read value</returns>
        public int ReadInt32()
        {
            return ReadInt32(false);
        }

        /// <summary>
        /// Read an unsigned integer from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns>The read value</returns>
        public uint ReadUInt32(bool littleEndian)
        {
            byte[] data = ReadBytes(4);

            return BitConverter.ToUInt32(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a big endian unsigned integer from the stream
        /// </summary>
        /// <returns>The read value</returns>
        public uint ReadUInt32()
        {
            return ReadUInt32(false);
        }

        /// <summary>
        /// Read an unsigned long from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns>The read value</returns>
        public ulong ReadUInt64(bool littleEndian)
        {
            byte[] data = ReadBytes(8);

            return BitConverter.ToUInt64(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a big endian unsigned long from the stream
        /// </summary>
        /// <returns>The read value</returns>
        public ulong ReadUInt64()
        {
            return ReadUInt64(false);
        }

        /// <summary>
        /// Read a long from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns>The read value</returns>
        public long ReadInt64(bool littleEndian)
        {
            byte[] data = ReadBytes(8);

            return BitConverter.ToInt64(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a big endian long from the stream
        /// </summary>
        /// <returns>The read value</returns>
        public long ReadInt64()
        {
            return ReadInt64(false);
        }

        /// <summary>
        /// Read a 24bit integer from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns>The 24bit integer</returns>
        public Int24 ReadInt24(bool littleEndian)
        {
            int ofs = littleEndian ? 0 : 1;
            byte[] data = new byte[4];

            for (int i = 0; i < 3; ++i)
            {
                data[i + ofs] = ReadByte();
            }

            // Sign the value
            if (littleEndian)
            {
                if ((data[2] & 0x80) != 0)
                {
                    data[3] = 0xFF;
                }
            }
            else
            {
                if ((data[1] & 0x80) != 0)
                {
                    data[0] = 0xFF;
                }
            }

            return (Int24)BitConverter.ToInt32(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a 24bit integer from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns>The 24bit unsigned integer</returns>
        public UInt24 ReadUInt24(bool littleEndian)
        {
            int ofs = littleEndian ? 0 : 1;
            byte[] data = new byte[4];

            for (int i = 0; i < 3; ++i)
            {
                data[i + ofs] = ReadByte();
            }

            return (UInt24)BitConverter.ToUInt32(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a big endian 24bit integer from the stream
        /// </summary>        
        /// <returns>The 24bit integer</returns>
        public Int24 ReadInt24()
        {
            return ReadInt24(false);
        }

        /// <summary>
        /// Read a big endian 24bit integer from the stream 
        /// </summary>        
        /// <returns>The 24bit unsigned integer</returns>
        public UInt24 ReadUInt24()
        {
            return ReadUInt24(false);
        }

        /// <summary>
        /// Read a big endian float from the stream
        /// </summary>
        /// <returns>The float</returns>
        public float ReadFloat()
        {
            return ReadFloat(false);
        }

        /// <summary>
        /// Read a float from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns>The float</returns>
        public float ReadFloat(bool littleEndian)
        {
            byte[] data = ReadBytes(4);

            return BitConverter.ToSingle(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a big endian double from the stream
        /// </summary>
        /// <returns>The double</returns>
        public double ReadDouble()
        {
            return ReadDouble(false);
        }

        /// <summary>
        /// Read a double from the stream with a specified endian
        /// </summary>
        /// <param name="littleEndian">True for little endian, false for big endian</param>
        /// <returns>The double</returns>
        public double ReadDouble(bool littleEndian)
        {
            byte[] data = ReadBytes(8);

            return BitConverter.ToDouble(GeneralUtils.SwapBytes(data, littleEndian), 0);
        }

        /// <summary>
        /// Read a primitive type
        /// </summary>
        /// <typeparam name="T">The primitive type to read</typeparam>
        /// <param name="littleEndian">Whether should read in little endian (if applicable)</param>
        /// <exception cref="ArgumentException">Throw if cannot determine type to read</exception>
        /// <returns>The primitive type</returns>
        public T ReadPrimitive<T>(bool littleEndian) where T : struct
        {
            return (T)ReadPrimitive(typeof(T), littleEndian);
        }

        /// <summary>
        /// Read a primitive type
        /// </summary>        
        /// <param name="t">The primitive type to read</param>
        /// <param name="littleEndian">Whether should read in little endian (if applicable)</param>
        /// <exception cref="ArgumentException">Throw if cannot determine type to read</exception>
        /// <returns>The primitive type</returns>
        public object ReadPrimitive(Type t, bool littleEndian)
        {
            object ret = null;
            if (t == typeof(byte))
            {
                ret = ReadByte();
            }
            else if (t == typeof(sbyte))
            {
                ret = ReadSByte();
            }
            else if (t == typeof(short))
            {
                ret = ReadInt16(littleEndian);
            }
            else if (t == typeof(ushort))
            {
                ret = ReadUInt16(littleEndian);
            }
            else if (t == typeof(int))
            {
                ret = ReadInt32(littleEndian);
            }
            else if (t == typeof(uint))
            {
                ret = ReadUInt32(littleEndian);
            }
            else if (t == typeof(long))
            {
                ret = ReadInt64(littleEndian);
            }
            else if (t == typeof(ulong))
            {
                ret = ReadUInt64(littleEndian);
            }
            else if (t == typeof(float))
            {
                ret = ReadFloat(littleEndian);
            }
            else if (t == typeof(double))
            {
                ret = ReadDouble(littleEndian);
            }
            else if (t == typeof(Int24))
            {
                ret = ReadInt24(littleEndian);
            }
            else if (t == typeof(UInt24))
            {
                ret = ReadUInt24(littleEndian);
            }
            else if (typeof(IPrimitiveValue).GetTypeInfo().IsAssignableFrom(t))
            {
                IPrimitiveValue ser = (IPrimitiveValue)Activator.CreateInstance(t);

                ser.FromReader(this, littleEndian);

                ret = ser;
            }
            else
            {
                throw new ArgumentException(String.Format(Properties.Resources.DataReader_InvalidPrimitiveType, t));
            }

            return ret;
        }

        /// <summary>
        /// Get the underlying stream object
        /// </summary>
        /// <returns>The stream object</returns>
        public Stream GetStream()
        {
            // Clear bits, we cannot ever be certain this won't do harm
            _validBits = 0;
            return _stm;
        }

        /// <summary>
        /// Gets the number of bytes left in the stream, -1 if not supported
        /// </summary>        
        public long DataLeft
        {
            get
            {
                try
                {
                    return _stm.Length - _stm.Position;
                }
                catch (NotSupportedException)
                {
                    return -1;
                }
            }
        }

        /// <summary>
        /// Get indication of end of file
        /// </summary>
        public bool Eof
        {
            get { return _eof; }
        }

        /// <summary>
        /// Read a specified number of bits from the stream
        /// </summary>
        /// <param name="count">The count of bits, should be between 0 and 64</param>
        /// <param name="littleEndian">Whether the bits are read out little endian, in little endian bits are read starting with LSB, in big endian they read from MSB</param>
        /// <returns>The read bits</returns>
        public ulong ReadBits(int count, bool littleEndian)
        {
            ulong ret = 0;

            if ((count < 0) || (count > 64))
            {
                throw new ArgumentException(CANAPE.Properties.Resources.DataReader_InvalidBitCount, "count");
            }

            for (int i = 0; i < count; ++i)
            {
                if (_validBits == 0)
                {
                    _currBits = ReadByte();
                    _validBits = 8;
                }

                if (littleEndian)
                {
                    // Set the LSB at the current location
                    ret |= ((ulong)_currBits & 1) << i;
                    _currBits >>= 1;
                }
                else
                {
                    // Set the MSB valid bit at the lowest position and shift current value
                    ret = (ret << 1) | (((ulong)_currBits >> 7) & 1);
                    _currBits <<= 1;
                }

                _validBits--;
            }

            return ret;
        }

        /// <summary>
        /// Read a specified number of big endian bits from the stream
        /// </summary>
        /// <param name="count">The count of bits, should be between 0 and 64</param>        
        /// <returns>The read bits</returns>
        public ulong ReadBits(int count)
        {
            return ReadBits(count, false);
        }

        /// <summary>
        /// Specifies how many bytes have been read since the last time the state was cleared
        /// </summary>
        public long ByteCount
        {
            get
            {
                return _stm.BytesRead;
            }

            set
            {
                _stm.BytesRead = value;
            }
        }
    }
}
