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
using System.Collections.Generic;
using System.Dynamic;

namespace CANAPE.Utils
{
    /// <summary>
    /// A read only configuration object backed by a dictionary
    /// </summary>
    public sealed class DynamicConfigObject : DynamicObject
    {
        private Dictionary<string, dynamic> _dict;

        /// <summary>
        /// Default constructor
        /// </summary>
        public DynamicConfigObject() : this(new Dictionary<string, dynamic>())
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="dict">The dictionary of properties</param>
        public DynamicConfigObject(Dictionary<string, dynamic> dict)
        {
            _dict = dict;
        }

        /// <summary>
        /// Method to get a member value from dictionary
        /// </summary>
        /// <param name="binder">The binder</param>
        /// <param name="result">The result</param>
        /// <returns>True if got the member</returns>
        public override bool TryGetMember(GetMemberBinder binder, out object result)
        {
            if (_dict.ContainsKey(binder.Name))
            {
                result = _dict[binder.Name];

                return true;
            }
            else
            {
                result = null;

                return false;
            }
        }
    }
}
