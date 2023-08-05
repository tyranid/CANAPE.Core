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
using CANAPE.DataFrames;
using System;
using System.IO;

namespace CANAPE.DataAdapters
{
    /// <summary>
    /// Class to implement a .NET stream based on a data adapter    
    /// </summary>
    public class DataAdapterToStream : Stream
    {
        private IDataAdapter _adapter;
        private byte[] _currBuf;
        private int _currPos;
        private bool _endOfStream;

        /// <summary>
        /// Default constructor
        /// </summary>
        public DataAdapterToStream(IDataAdapter adapter)
            : base()
        {
            _adapter = adapter;
        }

        /// <summary>
        /// Get the description
        /// </summary>
        public string Description { get { return _adapter.Description; } }

        #region Stream Implementation

        /// <summary>
        /// Whether the stream can be read (always true)
        /// </summary>
        public override bool CanRead
        {
            get { return true; }
        }

        /// <summary>
        /// Whether the stream can be seeked (always false)
        /// </summary>
        public override bool CanSeek
        {
            get { return false; }
        }

        /// <summary>
        /// Whether the stream can be written (always false)
        /// </summary>
        public override bool CanWrite
        {
            get { return true; }
        }

        /// <summary>
        /// Flush the stream (does nothing)
        /// </summary>
        public override void Flush()
        {
        }

        /// <summary>
        /// Get length of stream, always throws NotSupportedException
        /// </summary>
        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        /// <summary>
        /// Get or set position in stream, always throws NotSupportedException
        /// </summary>
        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        private bool CheckDataAvailable()
        {
            if ((_currBuf == null) || (_currPos == _currBuf.Length))
            {
                DataFrame frame = _adapter.Read();
                byte[] buf = null;

                if (frame != null)
                {
                    buf = frame.ToArray();
                }

                _currBuf = null;
                _currPos = 0;

                if (buf == null)
                {
                    _endOfStream = true;
                }
                else
                {
                    _currBuf = buf;
                    _currPos = 0;
                }
            }

            if ((_currBuf != null) && (_currBuf.Length > 0))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Read data from pipe
        /// </summary>
        /// <param name="buffer">The array to put the data into</param>
        /// <param name="offset">The offset into the array</param>
        /// <param name="count">The number of bytes to read</param>
        /// <returns>The length successfully read, 0 on end of stream</returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            int len = 0;

            if (!_endOfStream)
            {
                if (CheckDataAvailable())
                {
                    int left = _currBuf.Length - _currPos;
                    len = left < count ? left : count;

                    Buffer.BlockCopy(_currBuf, _currPos, buffer, offset, len);
                    _currPos += len;
                }
            }

            return len;
        }

        /// <summary>
        /// Read a byte
        /// </summary>
        /// <returns>The byte, -1 on end of stream</returns>
        public override int ReadByte()
        {
            int ret = -1;

            if (!_endOfStream)
            {
                if (CheckDataAvailable())
                {
                    ret = (int)_currBuf[_currPos++];
                }
            }

            return ret;
        }

        /// <summary>
        /// Seek (always throws NotSupportedException)
        /// </summary>
        /// <param name="offset">Offset</param>
        /// <param name="origin">Origin</param>
        /// <exception cref="NotSupportedException"></exception>
        /// <returns>N/A</returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Set the length of the stream (always throws NotSupportedException)
        /// </summary>
        /// <param name="value"></param>
        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Write to the stream 
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <param name="offset">Offset</param>
        /// <param name="count">Count</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            byte[] buf = new byte[count];

            Buffer.BlockCopy(buffer, offset, buf, 0, count);

            _adapter.Write(new ByteArrayDataFrame(buf));
        }

        /// <summary>
        /// Get or set the read timeout
        /// </summary>
        public override int ReadTimeout
        {
            get
            {
                return _adapter.ReadTimeout;
            }
            set
            {
                _adapter.ReadTimeout = value;
            }
        }

        #endregion

        /// <summary>
        /// Disposing method
        /// </summary>
        /// <param name="disposing"></param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (_adapter != null)
            {
                _adapter.Dispose();
            }
        }
    }
}
