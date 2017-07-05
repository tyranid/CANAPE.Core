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
namespace CANAPE.Utils
{
    /// <summary>
    /// The encoding to use if the selected nodes are not strings
    /// </summary>
    public enum BinaryStringEncoding
    {
        /// <summary>
        /// 8 bit ascii encoding
        /// </summary>
        ASCII,
        /// <summary>
        /// UTF8
        /// </summary>
        UTF8,
        /// <summary>
        /// UTF7
        /// </summary>
        UTF7,
        /// <summary>
        /// UTF16 little endian
        /// </summary>
        UTF16_LE,
        /// <summary>
        /// UTF16 big endian
        /// </summary>
        UTF16_BE,
        /// <summary>
        /// UTF32 little endian
        /// </summary>
        UTF32_LE,
        /// <summary>
        /// UTF32 big endian
        /// </summary>
        UTF32_BE,
        /// <summary>
        /// EBDIC (US)
        /// </summary>
        EBCDIC_US,
        /// <summary>
        /// IBM Latin 1
        /// </summary>
        Latin1,
        /// <summary>
        /// Shift-JIS (Japanese)
        /// </summary>
        ShiftJIS,
    }
}
