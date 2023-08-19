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

namespace CANAPE.Net.Filters
{
    /// <summary>
    /// An enumeration which indicates the layer merge policy
    /// </summary>
    public enum LayerMergePolicy
    {
        /// <summary>
        /// Add the layers to the end of the current list
        /// </summary>
        Suffix,

        /// <summary>
        /// Add the layers to the beginning of the current list
        /// </summary>
        Prefix,

        /// <summary>
        /// Replace the layers entirely
        /// </summary>
        Replace
    }
}
