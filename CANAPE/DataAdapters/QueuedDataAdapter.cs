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
using CANAPE.Utils;
using System;
using System.IO;
using System.Threading;

namespace CANAPE.DataAdapters
{
    /// <summary>
    /// A data adapter which acts like a queue, calling code can queue up a frame which will 
    /// travese a network and then dequeue data as it returns
    /// </summary>
    public class QueuedDataAdapter : BaseDataAdapter
    {
        private LockedQueue<DataFrame> _inputQueue;
        private LockedQueue<DataFrame> _outputQueue;
        private int _readTimeout;

        /// <summary>
        /// Constructor
        /// </summary>
        public QueuedDataAdapter(CancellationToken token)
        {
            _inputQueue = new LockedQueue<DataFrame>(-1, token);
            _outputQueue = new LockedQueue<DataFrame>(-1, token);
            _readTimeout = Timeout.Infinite;
        }

        /// <summary>
        /// Default constructor
        /// </summary>
        public QueuedDataAdapter()
            : this(CancellationToken.None)
        {
        }

        /// <summary>
        /// Read a frame from the output queue
        /// </summary>
        /// <returns>The frame, null on end of stream</returns>
        public override DataFrame Read()
        {
            DataFrame ret = null;

            try
            {
                if (!_outputQueue.Dequeue(_readTimeout, out ret))
                {
                    if (!_outputQueue.IsStopped)
                    {
                        throw new IOException();
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }

            return ret;
        }

        /// <summary>
        /// Writes a frame to the input queue
        /// </summary>
        /// <param name="data">The frame, null on end of stream</param>
        public override void Write(DataFrame data)
        {
            try
            {
                _inputQueue.Enqueue(data);
            }
            catch (InvalidOperationException)
            {
                // Couldn't queue, leave as is
            }
            catch (OperationCanceledException)
            {
            }
        }

        /// <summary>
        /// Dispose method, only closes input queue so you can no longer write to it
        /// </summary>
        /// <param name="disposing"></param>
        protected override void OnDispose(bool disposing)
        {
            _inputQueue.Stop();
        }

        /// <summary>
        /// Enqueue a frame on the outbound queue
        /// </summary>
        /// <param name="frame">The frame</param>
        public void Enqueue(DataFrame frame)
        {
            _outputQueue.Enqueue(frame);
        }

        /// <summary>
        /// Close the write queue down, this will cause the Read() method to return null when no more data
        /// </summary>
        public void StopEnqueue()
        {
            _outputQueue.Stop();
        }

        /// <summary>
        /// Dequeue a frame from the input queue
        /// </summary>
        /// <returns>The frame, null on end of stream</returns>
        public DataFrame Dequeue()
        {
            return Dequeue(Timeout.Infinite);
        }

        /// <summary>
        /// Dequeue a frame from the input queue with timeout
        /// </summary>
        /// <param name="readTimeout">Timeout in milliseconds</param>
        /// <returns>The frame, null on end of stream or timeout</returns>
        public DataFrame Dequeue(int readTimeout)
        {
            DataFrame ret = null;

            if (!_inputQueue.Dequeue(readTimeout, out ret))
            {
                // Indicates that we hit a timeout, throw an IOException
                if (!_inputQueue.IsStopped)
                {
                    throw new IOException();
                }
            }

            return ret;
        }

        /// <summary>
        /// Specify read timeout
        /// </summary>
        public override int ReadTimeout
        {
            get
            {
                return _readTimeout;
            }
            set
            {
                if ((value < 0) && (value != Timeout.Infinite))
                {
                    throw new ArgumentOutOfRangeException();
                }
                _readTimeout = value;
            }
        }
    }
}
