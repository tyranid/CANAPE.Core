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
using System.IO;

namespace CANAPE.DataFrames
{
    /// <summary>
    /// Complex data frame class.
    /// </summary>
    public sealed class ComplexDataFrame<T> : DataFrame where T : IDataValue<T>
    {
        private T _value;

        /// <summary>
        /// Gets the internal value.
        /// </summary>
        /// <returns>The internal value.</returns>
        protected override object GetInternalValue()
        {
            return _value;
        }

        /// <summary>
        /// Method called on clone
        /// </summary>
        protected override void OnClone()
        {
            _value = _value.Clone();
        }

        /// <summary>
        /// Convert the frame to a byte array
        /// </summary>
        // <returns>The data as an array</returns>
        public override byte[] ToArray()
        {
            MemoryStream stm = new MemoryStream();

            _value.ToWriter(new DataWriter(stm));

            return stm.ToArray();
        }

        /// <summary>
        /// Constructor, creates a basic frame with a known root
        /// </summary>
        internal ComplexDataFrame(T value)
        {
            _value = value;
        }

        /// <summary>
        /// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:CANAPE.DataFrames.ComplexDataFrame`1"/>.
        /// </summary>
        /// <returns>A <see cref="T:System.String"/> that represents the current <see cref="T:CANAPE.DataFrames.ComplexDataFrame`1"/>.</returns>
        public override string ToString()
        {
            return _value.ToString();
        }
    }
}
