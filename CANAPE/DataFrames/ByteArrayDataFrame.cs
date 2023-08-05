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
namespace CANAPE.DataFrames
{
    /// <summary>
    /// Byte array data frame.
    /// </summary>
    public sealed class ByteArrayDataFrame : DataFrame
    {
        private byte[] _value;

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.DataFrames.ByteArrayDataFrame"/> class.
        /// </summary>
        internal ByteArrayDataFrame()
            : this(new byte[0])
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="T:CANAPE.DataFrames.ByteArrayDataFrame"/> class.
        /// </summary>
        /// <param name="data">Data for frame</param>
        internal ByteArrayDataFrame(byte[] data)
        {
            _value = data;
        }

        private byte[] CloneData()
        {
            return (byte[])_value.Clone();
        }

        /// <summary>
        /// Gets the internal value.
        /// </summary>
        /// <returns>The internal value.</returns>
        protected override object GetInternalValue()
        {
            return _value;
        }

        /// <summary>
        /// Converts to a byte array
        /// </summary>
        /// <returns>The byte array.</returns>
        public override byte[] ToArray()
        {
            return CloneData();
        }

        /// <summary>
        /// Called on clone.
        /// </summary>
        protected override void OnClone()
        {
            _value = CloneData();
        }
    }
}
