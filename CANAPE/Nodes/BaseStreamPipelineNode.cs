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
using System.Threading;

namespace CANAPE.Nodes
{
    /// <summary>
    /// Pipeline node which converts incoming data frames into a stream
    /// </summary>
    public abstract class BaseStreamPipelineNode : BasePipelineNode
    {
        private PipelineStream _input;
        private object _lockObject;
        private Thread _thread;
        private bool _isDisposed;
        private CancellationTokenSource _cancel_source;

        const int MAX_BUFFER = 1024;

        /// <summary>
        /// Default constructor
        /// </summary>
        protected BaseStreamPipelineNode()
        {
            _cancel_source = new CancellationTokenSource();
            _input = new PipelineStream(_cancel_source.Token);
            _lockObject = new object();
        }

        /// <summary>
        /// Function called by the thread
        /// </summary>
        /// <param name="stm">Reading stream</param>
        protected abstract void OnRead(PipelineStream stm);

        private void ReadThread()
        {
            OnRead(_input);

            _input.Dispose();

            // Write end of pipe
            ShutdownOutputs();
        }

        private void EnsureThreadRunning()
        {
            lock (_lockObject)
            {
                if (_thread == null)
                {
                    _thread = new Thread(ReadThread);
                    _thread.Name = string.Format("Base Stream Thread {0}/{1}", Name, Uuid);
                    _thread.IsBackground = true;
                    _thread.Start();
                }
            }
        }

        /// <summary>
        /// Override function called when node is being shutdown
        /// </summary>
        protected override bool OnShutdown()
        {
            try
            {
                _input.Enqueue(null);
            }
            catch (InvalidOperationException)
            { }
            catch (OperationCanceledException)
            { }

            EnsureThreadRunning();

            return false;
        }

        /// <summary>
        /// Override function called when a packet is input
        /// </summary>
        /// <param name="frame"></param>
        protected override void OnInput(DataFrame frame)
        {
            try
            {
                _input.Enqueue(frame.ToArray());
            }
            catch (InvalidOperationException)
            { }
            catch (OperationCanceledException)
            { }

            EnsureThreadRunning();
        }

        /// <summary>
        /// Overidden dispose method
        /// </summary>
        /// <param name="disposing">True if should dispose of managed and unmanaged data</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (!_isDisposed)
            {
                _isDisposed = true;
                using (_cancel_source)
                {
                    _cancel_source?.Cancel();
                }

                try
                {
                    _input?.Dispose();
                }
                catch
                {
                }
            }
        }
    }
}
