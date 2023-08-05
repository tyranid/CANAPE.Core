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
using CANAPE.Utils;
using System.Collections.Generic;
using System.Text;

namespace CANAPE.DataFrames
{
    /// <summary>
    /// Class to add some extension methods to data adapters
    /// </summary>
    public static class DataFrameExtensions
    {
        /// <summary>
        /// Convert frames to an enumerator
        /// </summary>
        /// <param name="adapter">The data adapgter</param>
        /// <returns>An enumerator of frames</returns>
        public static IEnumerable<DataFrame> ReadFrames(this IDataAdapter adapter)
        {
            DataFrame frame = adapter.Read();

            while (frame != null)
            {
                yield return frame;

                frame = adapter.Read();
            }
        }



        /// <summary>
        /// Convert byte array to a data frame.
        /// </summary>
        /// <returns>The data frame.</returns>
        /// <param name="data">The byte array to convert</param>
        public static DataFrame ToDataFrame(this byte[] data)
        {
            return new ByteArrayDataFrame(data);
        }

        /// <summary>
        /// Convert string a binary string data frame.
        /// </summary>
        /// <returns>The data frame.</returns>
        /// <param name="data">The string to convert</param>
        public static DataFrame ToDataFrame(this string data)
        {
            return ToDataFrame(data, BinaryEncoding.Instance);
        }

        /// <summary>
        /// Convert string a binary string data frame.
        /// </summary>
        /// <returns>The data frame.</returns>
        /// <param name="data">The string to convert</param>
        /// <param name="encoding">The string encoding</param>
        public static DataFrame ToDataFrame(this string data, Encoding encoding)
        {
            return new StringDataFrame(data, encoding);
        }

        /// <summary>
        /// Convert a data value to a frame.
        /// </summary>
        /// <returns>The data frame.</returns>
        /// <param name="value">The value to convert.</param>
        public static DataFrame ToDataFrame<T>(this T value) where T : IDataValue<T>
        {
            return new ComplexDataFrame<T>(value);
        }
    }
}
