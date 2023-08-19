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
using System.Text;

namespace CANAPE.DataFrames
{
    /// <summary>
    /// String data frame.
    /// </summary>
    public sealed class StringDataFrame : DataFrame
    {
        private string _value;
        private Encoding _encoding;

        /// <summary>
        /// Gets the internal value.
        /// </summary>
        /// <returns>The internal value.</returns>
        protected override object GetInternalValue()
        {
            return _value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.DataFrames.StringDataFrame"/> class.
        /// </summary>
        internal StringDataFrame()
            : this(String.Empty, BinaryEncoding.Instance)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.DataFrames.StringDataFrame"/> class.
        /// </summary>
        /// <param name="value">The string value for Binary Encoding.</param>
        internal StringDataFrame(string value)
            : this(value, BinaryEncoding.Instance)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.DataFrames.StringDataFrame"/> class.
        /// </summary>
        /// <param name="data">The string value.</param>
        /// <param name="encoding">Text encoding.</param>
        public StringDataFrame(string data, Encoding encoding)
        {
            _value = data;
            _encoding = encoding;
        }

        /// <summary>
        /// Convert to a data string.
        /// </summary>
        /// <returns>The data string.</returns>
        public override string ToDataString()
        {
            return _value;
        }

        /// <summary>
        /// Converts to a byte array
        /// </summary>
        /// <returns>The byte array.</returns>
        public override byte[] ToArray()
        {
            return _encoding.GetBytes(_value);
        }
    }
}
