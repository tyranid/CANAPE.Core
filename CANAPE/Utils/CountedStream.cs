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
using System.IO;

namespace CANAPE.Utils
{
    /// <summary>
    /// A stream class which counts how many bytes have been read
    /// </summary>
    internal class CountedStream : Stream
    {
        private Stream _stm;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="stm">The stream to wrap</param>
        public CountedStream(Stream stm)
        {
            _stm = stm;
        }

        /// <summary>
        /// Can the stream be read
        /// </summary>
        public override bool CanRead
        {
            get { return _stm.CanRead; }
        }

        /// <summary>
        /// Can the stream seek
        /// </summary>
        public override bool CanSeek
        {
            get { return _stm.CanSeek; }
        }

        /// <summary>
        /// Can the stream be written to
        /// </summary>
        public override bool CanWrite
        {
            get { return _stm.CanWrite; }
        }

        /// <summary>
        /// Flush stream
        /// </summary>
        public override void Flush()
        {
            _stm.Flush();
        }

        /// <summary>
        /// Get stream length
        /// </summary>
        public override long Length
        {
            get { return _stm.Length; }
        }

        /// <summary>
        /// Get or set stream position
        /// </summary>
        public override long Position
        {
            get
            {
                return _stm.Position;
            }
            set
            {
                _stm.Position = value;
            }
        }

        /// <summary>
        /// Read from stream
        /// </summary>
        /// <param name="buffer">The buffer to read into</param>
        /// <param name="offset">The offset into the buffer</param>
        /// <param name="count">The number of bytes</param>
        /// <returns>The number of bytes read</returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            int ret = _stm.Read(buffer, offset, count);

            if (ret > 0)
            {
                BytesRead += ret;
            }

            return ret;
        }

        /// <summary>
        /// Seek in the stream
        /// </summary>
        /// <param name="offset">The seek offset</param>
        /// <param name="origin">The seek origin</param>
        /// <returns>The current position</returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            return _stm.Seek(offset, origin);
        }

        /// <summary>
        /// Set length of stream
        /// </summary>
        /// <param name="value">The value</param>
        public override void SetLength(long value)
        {
            _stm.SetLength(value);
        }

        /// <summary>
        /// Write to the stream
        /// </summary>
        /// <param name="buffer">The buffer to write</param>
        /// <param name="offset">The offset into the buffer</param>
        /// <param name="count">The number of bytes to write</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            _stm.Write(buffer, offset, count);

            if (count > 0)
            {
                BytesWritten += count;
            }
        }

        /// <summary>
        /// Read a byte from the stream
        /// </summary>
        /// <returns>The byte, -1 on end of stream</returns>
        public override int ReadByte()
        {
            int ret = _stm.ReadByte();
            if (ret >= 0)
            {
                BytesRead += 1;
            }

            return ret;
        }

        /// <summary>
        /// Write a byte to the stream
        /// </summary>
        /// <param name="value">The byte to write</param>
        public override void WriteByte(byte value)
        {
            _stm.WriteByte(value);
            BytesWritten += 1;
        }

        /// <summary>
        /// Get or set the number of bytes read
        /// </summary>
        public long BytesRead { get; set; }

        /// <summary>
        /// Get or set the number of bytes written
        /// </summary>
        public long BytesWritten { get; set; }
    }
}
