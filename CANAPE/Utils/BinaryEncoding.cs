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
using System.Text;

namespace CANAPE.Utils
{
    /// <summary>
    /// Encoding class to convert to and from binary data
    /// </summary>
    public sealed class BinaryEncoding : Encoding
    {
        private bool _encodeControl;

        /// <summary>
        /// Static instance of a binary encoding, as there is rarely a state there is rarely a reason to create a new one
        /// </summary>
        public static readonly BinaryEncoding Instance = new BinaryEncoding();

        static char[] BinaryMapTable = { '\x2302', '\x263a', '\x263b', '\x2665', '\x2666', '\x2663', '\x2660', '\x2022', '\x25d8', '\x25cb', '\x25d9', '\x2642', '\x2640',
                                       '\x266a', '\x266b', '\x263c', '\x25ba', '\x25c4', '\x2195', '\x203c', '\x2591', '\x2593', '\x25ac', '\x21a8', '\x2191', '\x2193',
                                       '\x2192', '\x2190', '\x221f', '\x2194', '\x25b2', '\x25bc'};

        /// <summary>
        /// Default constructor
        /// </summary>
        public BinaryEncoding()
            : this(false)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="encodeControl">Indicates control characters are changed</param>        
        public BinaryEncoding(bool encodeControl)
        {
            _encodeControl = encodeControl;
        }

        /// <summary>
        /// Get encoding name
        /// </summary>
        public override string EncodingName
        {
            get
            {
                return "Binary";
            }
        }

        /// <summary>
        /// Get the number of bytes
        /// </summary>
        /// <param name="chars"></param>
        /// <param name="index"></param>
        /// <param name="count"></param>
        /// <returns>Always count</returns>
        public override int GetByteCount(char[] chars, int index, int count)
        {
            return count;
        }

        /// <summary>
        /// Get bytes
        /// </summary>
        /// <param name="chars"></param>
        /// <param name="charIndex"></param>
        /// <param name="charCount"></param>
        /// <param name="bytes"></param>
        /// <param name="byteIndex"></param>
        /// <returns></returns>
        public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
        {
            if (_encodeControl)
            {
                for (int i = 0; i < charCount; ++i)
                {
                    char c = chars[charIndex + i];

                    if ((int)c > 255)
                    {
                        int j = 0;

                        for (j = 0; j < 32; ++j)
                        {
                            if (BinaryMapTable[j] == c)
                            {
                                bytes[byteIndex + i] = (byte)j;
                                break;
                            }
                        }

                        if (j == 32)
                        {
                            bytes[byteIndex + i] = (byte)c;
                        }
                    }
                    else
                    {
                        bytes[byteIndex + i] = (byte)c;
                    }
                }
            }
            else
            {
                for (int i = 0; i < charCount; ++i)
                {
                    bytes[byteIndex + i] = (byte)chars[charIndex + i];
                }
            }

            return charCount;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="index"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public override int GetCharCount(byte[] bytes, int index, int count)
        {
            return count;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="byteIndex"></param>
        /// <param name="byteCount"></param>
        /// <param name="chars"></param>
        /// <param name="charIndex"></param>
        /// <returns></returns>
        public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
        {
            if (_encodeControl)
            {
                for (int i = 0; i < byteCount; ++i)
                {
                    byte b = bytes[byteIndex = i];

                    if ((b < 32) && (b != 10) && (b != 13) && (b != 9))
                    {
                        chars[charIndex + i] = BinaryMapTable[b];
                    }
                    else
                    {
                        chars[charIndex + i] = (char)b;
                    }
                }
            }
            else
            {
                for (int i = 0; i < byteCount; ++i)
                {
                    chars[charIndex + i] = (char)bytes[byteIndex + i];
                }
            }

            return byteCount;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="charCount"></param>
        /// <returns></returns>
        public override int GetMaxByteCount(int charCount)
        {
            return charCount;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="byteCount"></param>
        /// <returns></returns>
        public override int GetMaxCharCount(int byteCount)
        {
            return byteCount;
        }

        /// <summary>
        /// Indicates this is a single byte encoding
        /// </summary>
        public override bool IsSingleByte
        {
            get
            {
                return true;
            }
        }
    }
}
