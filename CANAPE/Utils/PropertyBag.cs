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
using System;
using System.Collections.Generic;
using System.Linq;

namespace CANAPE.Utils
{
    /// <summary>
    /// A class to maintain a set of read only properties
    /// </summary>
    public sealed class PropertyBag : IDisposable, IEnumerable<KeyValuePair<string, object>>
    {
        private Dictionary<string, PropertyBag> _bags;
        private Dictionary<string, dynamic> _values;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="name">The name of the bag</param>
        public PropertyBag(string name)
        {
            _bags = new Dictionary<string, PropertyBag>();
            _values = new Dictionary<string, dynamic>();
            Name = name;
        }

        /// <summary>
        /// Default constructor
        /// </summary>
        public PropertyBag() : this("Root")
        {
        }

        /// <summary>
        /// Get name of bag
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Get values for bag
        /// </summary>
        public IEnumerable<dynamic> Values { get { return _values.Values; } }

        /// <summary>
        /// Get sub-bags
        /// </summary>
        public IEnumerable<PropertyBag> Bags { get { return _bags.Values; } }

        /// <summary>
        /// Add a new named bag, if already exists will return the current one
        /// </summary>
        /// <param name="name">The name of the bag</param>
        /// <returns>The new bag</returns>
        public PropertyBag AddBag(string name)
        {
            if (_bags.ContainsKey(name))
            {
                return _bags[name];
            }
            else
            {
                PropertyBag bag = new PropertyBag(name);

                _bags.Add(name, bag);

                return bag;
            }
        }

        /// <summary>
        /// Add an existing bag
        /// </summary>
        /// <param name="bag">The bag</param>
        public void AddBag(PropertyBag bag)
        {
            _bags.Add(bag.Name, bag);
        }

        /// <summary>
        /// Remove a bag
        /// </summary>
        /// <param name="name">The name of the bag</param>
        public void RemoveBag(string name)
        {
            _bags.Remove(name);
        }

        /// <summary>
        /// Add a value
        /// </summary>
        /// <param name="name">The name of the value</param>
        /// <param name="value">The value </param>
        public void AddValue(string name, dynamic value)
        {
            _values[name] = value;
        }

        /// <summary>
        /// Remove a value
        /// </summary>
        /// <param name="name">The name of the value</param>
        public void RemoveValue(string name)
        {
            _values.Remove(name);
        }

        /// <summary>
        /// Determine if the bag contains a named value
        /// </summary>
        /// <param name="name">The name</param>
        /// <returns>True if the value exists</returns>
        public bool ContainsValue(string name)
        {
            return _values.ContainsKey(name);
        }

        /// <summary>
        /// Determine if the bag contains a named bag
        /// </summary>
        /// <param name="name">The name</param>
        /// <returns>True if the bag exists</returns>
        public bool ContainsBag(string name)
        {
            return _bags.ContainsKey(name);
        }

        private PropertyBag GetRelativeBag(IEnumerable<string> parts)
        {
            PropertyBag bag = this;

            foreach (string name in parts)
            {
                if (bag._bags.ContainsKey(name))
                {
                    bag = _bags[name];
                }
                else
                {
                    bag = null;
                    break;
                }
            }

            return bag;
        }

        /// <summary>
        /// Get a bag with a dotted name
        /// </summary>
        /// <param name="name">The name in dotted form, e.g. com.test first searchs for the com bag, then test bag</param>
        /// <returns>The bag, or null if not found</returns>
        public PropertyBag GetRelativeBag(string name)
        {
            return GetRelativeBag(name.Split('.'));
        }

        /// <summary>
        /// Get a value with a dotted name
        /// </summary>
        /// <param name="name">The name in dotted form, e.g. com.test.MyValue first searchs for the com bag, then test bag, then MyValue</param>
        /// <returns>The value or null if not found</returns>
        public dynamic GetRelativeValue(string name)
        {
            dynamic ret = null;
            string[] parts = name.Split('.');

            if (parts.Length > 0)
            {
                PropertyBag bag = GetRelativeBag(parts.Take(parts.Length - 1));

                if (bag != null)
                {
                    if (bag._values.ContainsKey(parts[parts.Length - 1]))
                    {
                        ret = bag._values[parts[parts.Length - 1]];
                    }
                }
            }

            return ret;
        }

        /// <summary>
        /// Clear the entire bag
        /// </summary>
        public void Clear()
        {
            _bags.Clear();
            _values.Clear();
        }

        #region IDisposable Members

        /// <summary>
        /// Dispose of the bag and call dispose on its contents
        /// </summary>
        void IDisposable.Dispose()
        {
            foreach (PropertyBag bag in _bags.Values)
            {
                ((IDisposable)bag).Dispose();
            }

            foreach (IDisposable d in _values.Values.Where(v => v is IDisposable))
            {
                d.Dispose();
            }
        }

        #endregion

        /// <summary>
        /// Get an enumerator
        /// </summary>
        /// <returns>The enumerator</returns>
        public IEnumerator<KeyValuePair<string, object>> GetEnumerator()
        {
            foreach (KeyValuePair<string, PropertyBag> bag in _bags)
            {
                foreach (KeyValuePair<string, dynamic> pair in bag.Value)
                {
                    yield return new KeyValuePair<string, object>(String.Format("{0}.{1}", bag.Key, pair.Key), pair.Value);
                }
            }

            foreach (KeyValuePair<string, object> value in _values)
            {
                yield return value;
            }
        }

        /// <summary>
        /// IEnumerable method
        /// </summary>
        /// <returns>The enumerator</returns>
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return this.GetEnumerator();
        }
    }
}
