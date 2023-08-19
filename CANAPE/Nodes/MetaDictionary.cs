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
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace CANAPE.Nodes
{
    /// <summary>
    /// Meta data dictionary
    /// </summary>
    public class MetaDictionary : ConcurrentDictionary<string, dynamic>
    {
        /// <summary>
        /// Default constructor
        /// </summary>
        public MetaDictionary()
            : base()
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="e">An enumerable object to use</param>
        public MetaDictionary(IEnumerable<KeyValuePair<string, dynamic>> e)
            : base(e)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>        
        /// <param name="dict">Other dictionary</param>
        public MetaDictionary(MetaDictionary dict)
            : base(dict.ToArray())
        {
        }

        private dynamic GetMetaInternal(string name, dynamic defaultValue)
        {
            dynamic ret = null;

            if (!TryGetValue(name, out ret))
            {
                if (defaultValue != null)
                {
                    ret = GetOrAdd(name, defaultValue);
                }
            }

            return ret;
        }

        private void SetMetaInternal(string name, dynamic value)
        {
            if (value != null)
            {
                this[name] = value;
            }
            else
            {
                dynamic val;
                TryRemove(name, out val);
            }
        }

        private int GetCounterInternal(string name, int defaultValue)
        {
            return GetMetaInternal(name, defaultValue);
        }

        private void SetCounterInternal(string name, int value)
        {
            SetMetaInternal(name, value);
        }

        /// <summary>
        /// Increment a counter
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="startValue">The initial value of the counter</param>
        /// <param name="increment">The value to increment the counter by if it exists</param>
        /// <returns>The current value of the counter</returns>
        public int IncrementCounter(string name, int startValue, int increment)
        {
            return AddOrUpdate(name, startValue, (s, x) => x + increment);
        }

        /// <summary>
        /// Increment a counter (long)
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="startValue">The initial value of the counter</param>
        /// <param name="increment">The value to increment the counter by if it exists</param>
        /// <returns>The current value of the counter</returns>
        public long IncrementCounterLong(string name, long startValue, long increment)
        {
            return AddOrUpdate(name, startValue, (s, x) => x + increment);
        }

        /// <summary>
        /// Get a meta value from the public scope
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>         
        /// <returns>The dynamic object or null if not found</returns>        
        public dynamic GetMeta(string name)
        {
            return GetMeta(name, null);
        }

        /// <summary>
        /// Get a meta value from the public scope, if it does not exist then add to the meta
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>     
        /// <param name="defaultValue">The default value to add, if null no value will be added</param>
        /// <returns>The dynamic object the default value if it does not exist</returns>   
        public dynamic GetMeta(string name, dynamic defaultValue)
        {
            return GetMetaInternal(name, defaultValue);
        }

        /// <summary>
        /// Set a meta value
        /// </summary>
        /// <param name="name">The name of the meta parameter</param>
        /// <param name="obj">The dynamic object, set to null to remove</param>
        public void SetMeta(string name, dynamic obj)
        {
            SetMetaInternal(name, obj);
        }

        /// <summary>
        /// Get a counter from the meta
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="defaultValue">The default value if it doesn't exist</param>
        /// <returns>The current value of the counter</returns>
        public int GetCounter(string name, int defaultValue)
        {
            return GetCounterInternal(name, defaultValue);
        }

        /// <summary>
        /// Increment a counter, will add if it doesn't exist (starting from 0)
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="increment">The value to increment the counter by</param>
        /// <returns>The new value of the counter</returns>
        public int IncrementCounter(string name, int increment)
        {
            return IncrementCounter(name, 0, increment);
        }

        /// <summary>
        /// Increment a counter (long), will add if it doesn't exist (starting from 0)
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="increment">The value to increment the counter by</param>
        /// <returns>The new value of the counter</returns>
        public long IncrementCounterLong(string name, long increment)
        {
            return IncrementCounterLong(name, 0, increment);
        }

        /// <summary>
        /// Set a counter to a specific value
        /// </summary>
        /// <param name="name">The name of the counter</param>
        /// <param name="value">The value of the counter</param>
        public void SetCounter(string name, int value)
        {
            SetCounterInternal(name, value);
        }
    }
}
