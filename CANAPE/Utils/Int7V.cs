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
using System.Globalization;

namespace CANAPE.Utils
{
    /// <summary>
    /// Dummy structure to represent a 7bit integer
    /// </summary>
    public struct Int7V : IConvertible, IFormattable, IComparable, IComparable<Int7V>, IEquatable<Int7V>, IPrimitiveValue
    {
        long value;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="value">The integer value</param>
        public Int7V(long value)
        {
            this.value = value;
        }

        /// <summary>
        /// Conversion operator to int
        /// </summary>
        /// <param name="right">The structure</param>
        /// <returns>The value</returns>
        public static explicit operator int(Int7V right)
        {
            return (int)right.value;
        }

        /// <summary>
        /// Conversion operator to uint
        /// </summary>
        /// <param name="right">The structure</param>
        /// <returns>The value</returns>
        public static explicit operator uint(Int7V right)
        {
            return (uint)right.value;
        }

        /// <summary>
        /// Conversion operator to long
        /// </summary>
        /// <param name="right">The structure</param>
        /// <returns>The value</returns>
        public static explicit operator long(Int7V right)
        {
            return right.value;
        }

        /// <summary>
        /// Conversion operator to ulong
        /// </summary>
        /// <param name="right">The structure</param>
        /// <returns>The value</returns>
        public static explicit operator ulong(Int7V right)
        {
            return (ulong)right.value;
        }

        /// <summary>
        /// Conversion operator to Int7V
        /// </summary>
        /// <param name="right">The integer</param>
        /// <returns>The structure</returns>
        public static explicit operator Int7V(int right)
        {
            return new Int7V(right);
        }

        /// <summary>
        /// Conversion operator to Int7V
        /// </summary>
        /// <param name="right">The integer</param>
        /// <returns>The structure</returns>
        public static explicit operator Int7V(uint right)
        {
            return new Int7V(right);
        }

        /// <summary>
        /// Conversion operator to Int7V
        /// </summary>
        /// <param name="right">The long integer</param>
        /// <returns>The structure</returns>
        public static explicit operator Int7V(long right)
        {
            return new Int7V(right);
        }

        TypeCode IConvertible.GetTypeCode()
        {
            return TypeCode.Object;
        }

        bool IConvertible.ToBoolean(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToBoolean(provider);
        }

        byte IConvertible.ToByte(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToByte(provider);
        }

        char IConvertible.ToChar(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToChar(provider);
        }

        DateTime IConvertible.ToDateTime(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToDateTime(provider);
        }

        decimal IConvertible.ToDecimal(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToDecimal(provider);
        }

        double IConvertible.ToDouble(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToDouble(provider);
        }

        short IConvertible.ToInt16(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToInt16(provider);
        }

        int IConvertible.ToInt32(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToInt32(provider);
        }

        long IConvertible.ToInt64(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToInt64(provider);
        }

        sbyte IConvertible.ToSByte(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToSByte(provider);
        }

        float IConvertible.ToSingle(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToSingle(provider);
        }

        string IConvertible.ToString(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToString(provider);
        }

        object IConvertible.ToType(Type conversionType, IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToType(conversionType, provider);
        }

        ushort IConvertible.ToUInt16(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToUInt16(provider);
        }

        uint IConvertible.ToUInt32(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToUInt32(provider);
        }

        ulong IConvertible.ToUInt64(IFormatProvider provider)
        {
            IConvertible conv = (IConvertible)value;

            return conv.ToUInt64(provider);
        }

        /// <summary>
        /// Convert to a string 
        /// </summary>
        /// <returns>The string</returns>
        public override string ToString()
        {
            return ToString(CultureInfo.CurrentCulture);
        }

        /// <summary>
        /// Convert to a string using a format
        /// </summary>
        /// <param name="s">The format string</param>
        /// <returns>The string</returns>
        public string ToString(string s)
        {
            return ToString(s, CultureInfo.CurrentCulture);
        }

        /// <summary>
        /// Convert to a string using a provider
        /// </summary>
        /// <param name="provider">The provider</param>
        /// <returns>The string</returns>
        public string ToString(IFormatProvider provider)
        {
            return value.ToString(provider);
        }

        /// <summary>
        /// Convert to a string using a format and provider
        /// </summary>
        /// <param name="s">The format string</param>
        /// <param name="provider">The provider</param>
        /// <returns>The string</returns>
        public string ToString(string s, IFormatProvider provider)
        {
            return value.ToString(s, provider);
        }

        /// <summary>
        /// Test for equality
        /// </summary>
        /// <param name="obj">The object to test</param>
        /// <returns>True if the object is equal</returns>
        public override bool Equals(object obj)
        {
            if (obj is Int7V)
            {
                return Equals((Int7V)obj);
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Equals operator
        /// </summary>
        /// <param name="left">Left hand object</param>
        /// <param name="right">Right hand object</param>
        /// <returns>True if object is equal</returns>
        public static bool operator ==(Int7V left, Int7V right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// Not equal operator
        /// </summary>
        /// <param name="left">Left hand object</param>
        /// <param name="right">Right hand object</param>
        /// <returns>True if object is not equal</returns>
        public static bool operator !=(Int7V left, Int7V right)
        {
            return !left.Equals(right);
        }

        /// <summary>
        /// Get hash code
        /// </summary>
        /// <returns>The hashcode</returns>
        public override int GetHashCode()
        {
            return value.GetHashCode();
        }

        /// <summary>
        /// Compare two objects
        /// </summary>
        /// <param name="obj">The object to compare against</param>
        /// <returns>less than 0 if less than, 0 if equal, greater if greater or null</returns>
        /// <exception cref="ArgumentException">Thrown if obj is not an Int7V</exception>
        public int CompareTo(object obj)
        {
            if (obj is Int7V)
            {
                return CompareTo((Int7V)obj);
            }
            else if (obj == null)
            {
                return 1;
            }
            else
            {
                throw new ArgumentException("Invalid compare object");
            }
        }

        /// <summary>
        /// Compare two objects
        /// </summary>
        /// <param name="other">The object to compare against</param>
        /// <returns>less than 0 if less than, 0 if equal, greater if greater</returns>
        public int CompareTo(Int7V other)
        {
            return value.CompareTo(other.value);
        }

        /// <summary>
        /// Test for equality
        /// </summary>
        /// <param name="other">The other value</param>
        /// <returns>True if equal</returns>
        public bool Equals(Int7V other)
        {
            return other.value == value;
        }

        /// <summary>
        /// Write the object to a stream
        /// </summary>
        /// <param name="writer">The writer to write the stream to</param>
        /// <param name="littleEndian">Whether the value should be little or big endian</param>
        public void ToWriter(DataWriter writer, bool littleEndian)
        {
            writer.WriteInt7V((ulong)value);
        }

        /// <summary>
        /// Read the object from a stream
        /// </summary>
        /// <param name="reader">The reader</param>
        /// <param name="littleEndian">Whether the value shouldbe little or big endian</param>
        public void FromReader(DataReader reader, bool littleEndian)
        {
            this.value = (long)reader.ReadInt7V();
        }

        /// <summary>
        /// Get or set the value
        /// </summary>
        public object Value
        {
            get
            {
                return value;
            }
            set
            {
                this.value = Convert.ToInt64(value);
            }
        }
    }

}
