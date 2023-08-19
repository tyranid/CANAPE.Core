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
    /// A pipeline node which has its input and output decoupled by a thread
    /// </summary>
    public abstract class BaseDecoupledPipelineNode : BasePipelineNode
    {
        private CancellationTokenSource _cancel_source;
        private LockedQueue<DataFrame> _input;
        private object _lockObject;
        private Thread _thread;
        private bool _isDisposed;

        /// <summary>
        /// Default constructor
        /// </summary>
        protected BaseDecoupledPipelineNode()
        {
            _cancel_source = new CancellationTokenSource();
            _input = new LockedQueue<DataFrame>(-1, _cancel_source.Token);
            _lockObject = new object();
        }

        private void ReadThread()
        {
            try
            {
                DataFrame frame = _input.Dequeue();

                while (frame != null)
                {
                    // Call original Input method to kick off process
                    base.Input(frame);

                    frame = _input.Dequeue();
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                Graph.Logger.LogException(ex);
            }

            // Stop anything more arriving
            _input.Stop();

            if (!_isDisposed)
            {
                ShutdownOutputs();
            }
        }

        private void EnsureThreadRunning()
        {
            lock (_lockObject)
            {
                if (_thread == null)
                {
                    _thread = new Thread(ReadThread);
                    _thread.Name = string.Format("Base Pipeline Thread {0}/{1}", Name, Uuid);
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
            _input.Stop();
            EnsureThreadRunning();

            return false;
        }

        /// <summary>
        /// Override function called when a packet is input
        /// </summary>
        /// <param name="frame">The input frame</param>
        public override void Input(DataFrame frame)
        {
            EnsureThreadRunning();

            try
            {
                _input.Enqueue(frame);
            }
            catch (InvalidOperationException)
            { }
            catch (OperationCanceledException)
            { }
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
                if (disposing)
                {
                    _input.Stop();
                }
                using (_cancel_source)
                {
                    _cancel_source?.Cancel();
                }
            }
        }
    }
}
