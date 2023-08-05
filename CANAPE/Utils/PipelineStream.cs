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
using System.IO;
using System.Threading;

namespace CANAPE.Utils
{
    /// <summary>
    /// Class to implement a thread safe pipe byte stream
    /// inputs in blocks of bytes
    /// </summary>
    public class PipelineStream : Stream
    {
        byte[] _currBuf;
        int _currPos;
        LockedQueue<byte[]> _dataQueue;
        bool _endOfStream;
        int _readTimeout;

        /// <summary>
        /// Default constructor
        /// </summary>
        public PipelineStream(CancellationToken token)
        {
            _dataQueue = new LockedQueue<byte[]>(-1, token);
            _readTimeout = Timeout.Infinite;
        }

        /// <summary>
        /// Enqueue an array of bytes onto the pipeline
        /// </summary>
        /// <param name="frame">Array of bytes to queue, 
        /// if null is passed this will cause the stream to end when all data has been read</param>
        public void Enqueue(byte[] frame)
        {
            _dataQueue.Enqueue(frame);
        }

        /// <summary>
        /// Provide an indication if this stream has received an end of file
        /// </summary>
        public bool Eof { get { return _endOfStream; } }

        #region Stream Implementation

        /// <summary>
        /// Get or set stream timeout
        /// </summary>
        public override int ReadTimeout
        {
            get
            {
                return _readTimeout;
            }
            set
            {
                _readTimeout = value;
            }
        }

        /// <summary>
        /// Returns whether this stream can timeout
        /// </summary>
        public override bool CanTimeout
        {
            get
            {
                return true;
            }
        }

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
            get { return false; }
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

        private void EnsureDataAvailable()
        {
            if ((_currBuf == null) || (_currPos == _currBuf.Length))
            {
                if (!_dataQueue.Dequeue(_readTimeout, out _currBuf))
                {
                    if (!_dataQueue.IsStopped)
                    {
                        throw new IOException();
                    }
                }

                _currPos = 0;

                if (_currBuf == null)
                {
                    _endOfStream = true;
                }
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
                EnsureDataAvailable();

                if ((_currBuf != null) && (_currBuf.Length > 0))
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
                EnsureDataAvailable();

                if ((_currBuf != null) && (_currBuf.Length > 0))
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
        /// Write to the stream (always throws NotSupportedException)
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <param name="offset">Offset</param>
        /// <param name="count">Count</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Dispose method
        /// </summary>
        /// <param name="disposing">True is disposing, else finalizing</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _dataQueue.Stop();
        }

        #endregion
    }
}
