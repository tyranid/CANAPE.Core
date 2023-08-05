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

namespace CANAPE.DataFrames
{
    /// <summary>
    /// A DataFrame object
    /// </summary>
    public abstract class DataFrame
    {
        private string _hash;
        private long? _length;

        /// <summary>
        /// Methods called after clone.
        /// </summary>
        protected virtual void OnClone()
        {
            // Do nothing.
        }

        /// <summary>
        /// Clone the frame
        /// </summary>
        /// <returns>The cloned frame</returns>
        public DataFrame Clone()
        {
            DataFrame ret = (DataFrame)MemberwiseClone();
            ret.OnClone();
            return ret;
        }

        /// <summary>
        /// Gets the internal value.
        /// </summary>
        /// <returns>The internal value.</returns>
        protected abstract object GetInternalValue();

        /// <summary>
        /// Gets the value as a dynamic object.
        /// </summary>
        /// <returns>The value as a dynamic object</returns>
        public dynamic GetValue()
        {
            return GetInternalValue();
        }

        /// <summary>
        /// Gets the value.
        /// </summary>
        /// <returns>The value.</returns>
        /// <typeparam name="T">The type of the value you want.</typeparam>
        /// <exception cref="InvalidCastException">Thrown in can't cast to this type</exception>
        public T GetValue<T>()
        {
            return (T)GetInternalValue();
        }

        /// <summary>
        /// Gets the value but doesn't throw if not valid conversion. Instead returns
        /// the default value for the type.
        /// </summary>
        /// <returns>The value.</returns>
        /// <typeparam name="T">The type of the value you want.</typeparam>
        public T GetValueNoThrow<T>()
        {
            object value = GetInternalValue();
            if (value is T)
            {
                return (T)value;
            }
            return default(T);
        }

        /// <summary>
        /// Convert the frame to a byte array
        /// </summary>
        // <returns>The data as an array</returns>
        public abstract byte[] ToArray();

        /// <summary>
        /// Convert the frame to a data string
        /// </summary>
        /// <returns>The data string</returns>
        public virtual string ToDataString()
        {
            return BinaryEncoding.Instance.GetString(ToArray());
        }

        private void UpdateData()
        {
            try
            {
                byte[] data = ToArray();
                _length = data.Length;
                _hash = GeneralUtils.GenerateMd5String(data);
            }
            catch
            {
                _length = 0;
                _hash = "";
            }
        }

        /// <summary>
        /// MD5 hash of the frame
        /// </summary>
        public string Hash
        {
            get
            {
                if (_hash == null)
                {
                    UpdateData();
                }

                return _hash;
            }
        }

        /// <summary>
        /// Cached length of the frame
        /// </summary>
        public long Length
        {
            get
            {
                if (!_length.HasValue)
                {
                    UpdateData();
                }

                return _length.Value;
            }
        }


        /// <summary>
        /// Converts the node to a display string of sorts
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return ToDataString();
        }
    }
}
