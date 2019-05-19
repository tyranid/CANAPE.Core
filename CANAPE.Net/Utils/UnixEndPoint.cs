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
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CANAPE.Net.Utils
{
    /// <summary>
    /// Endpoint implementation for a AF_UNIX socket.
    /// </summary>
    [Serializable]
    public class UnixEndPoint : EndPoint
    {
        private const int UNIX_PATH_MAX = 108;
        private byte[] _path_bytes;

        private string GetPath()
        {
            if (_path_bytes.Length == 0 || _path_bytes[0] == '\0')
            {
                return string.Empty;
            }
            return Encoding.UTF8.GetString(_path_bytes).TrimEnd('\0');
        }

        /// <summary>
        /// Default constructor.
        /// </summary>
        public UnixEndPoint()
        {
            _path_bytes = new byte[0];
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="path">The path to the unix socket.</param>
        public UnixEndPoint(string path)
        {
            Path = path;
        }

        /// <summary>
        /// Get or set the path.
        /// </summary>
        public string Path
        {
            get => GetPath();
            set
            {
                byte[] path_bytes = Encoding.UTF8.GetBytes(value + "\0");
                if (path_bytes.Length > UNIX_PATH_MAX)
                {
                    throw new ArgumentException("Path can't be longer than 108 bytes including terminator");
                }
                _path_bytes = path_bytes;
            }
        }

        /// <summary>
        /// Address family.
        /// </summary>
        public override AddressFamily AddressFamily => AddressFamily.Unix;

        /// <summary>
        /// Serialize the socket address.
        /// </summary>
        /// <returns>The serialized address.</returns>
        public override SocketAddress Serialize()
        {
            // At least on Windows you need to allocate the entire address otherwise bad things happen.
            var addr = new SocketAddress(AddressFamily.Unix, 110);
            // The first two bytes should already be filled out.
            for (int i = 0; i < _path_bytes.Length; ++i)
            {
                addr[i + 2] = _path_bytes[i];
            }
            return addr;
        }

        /// <summary>
        /// Create a endpoint from a socket address.
        /// </summary>
        /// <param name="socketAddress">The socket address.</param>
        /// <returns>The created endpoint.</returns>
        public override EndPoint Create(SocketAddress socketAddress)
        {
            var ep = new UnixEndPoint
            {
                _path_bytes = new byte[socketAddress.Size - 2]
            };
            var family = (AddressFamily)(socketAddress[0] | (socketAddress[1] << 8));
            if (family != AddressFamily.Unix)
            {
                throw new ArgumentException("Family in socket address isn't AF_UNIX");
            }

            for (int i = 0; i < socketAddress.Size - 2; ++i)
            {
                ep._path_bytes[i] = socketAddress[i + 2];
            }
            return ep;
        }

        /// <summary>
        /// Overridden ToString method.
        /// </summary>
        /// <returns>The endpoint as a string.</returns>
        public override string ToString()
        {
            return Path;
        }

        /// <summary>
        /// Overridden equals method.
        /// </summary>
        /// <param name="obj">The object to compare.</param>
        /// <returns>True if the objects are equal.</returns>
        public override bool Equals(object obj)
        {
            if (!(obj is UnixEndPoint))
            {
                return false;
            }

            UnixEndPoint ep = (UnixEndPoint)obj;
            if (ep._path_bytes.Length != _path_bytes.Length)
            {
                return false;
            }

            for (int i = 0; i < _path_bytes.Length; ++i)
            {
                if (_path_bytes[i] != ep._path_bytes[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Get endpoint hash code.
        /// </summary>
        /// <returns>The hashcode.</returns>
        public override int GetHashCode()
        {
            return _path_bytes.Aggregate(0, (a, b) => a ^ b);
        }
    }
}
