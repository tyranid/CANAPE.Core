//    CANAPE Network Testing Tool
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

using System.Collections.Generic;
using CANAPE.Utils;

namespace CANAPE.DataFrames
{
    /// <summary>
    /// Equality comparer to just compare frames as bytes
    /// </summary>
    public class BasicDataFrameEqualityComparer : IEqualityComparer<DataFrame>
    {
        //TODO: Maybe optimize by saving byte arrays

        /// <summary>
        /// Whether the two frames are equal
        /// </summary>
        /// <param name="x">Left frame</param>
        /// <param name="y">Right frame</param>
        /// <returns></returns>
        public bool Equals(DataFrame x, DataFrame y)
        {
            return GeneralUtils.CompareBytes(x.ToArray(), y.ToArray());
        }

        /// <summary>
        /// Get hash code of frame
        /// </summary>
        /// <param name="obj">The frame</param>
        /// <returns>The hash code</returns>
        public int GetHashCode(DataFrame obj)
        {
            return GeneralUtils.GetBytesHashCode(obj.ToArray());
        }
    }
}
