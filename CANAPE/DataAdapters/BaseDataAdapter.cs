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

namespace CANAPE.DataAdapters
{
    /// <summary>
    /// Base class for DataAdapters
    /// </summary>
    public abstract class BaseDataAdapter : IDataAdapter
    {
        private bool _isDisposed;

        #region IDataAdapter Members

        /// <summary>
        /// Read a data frame from the underlying provider
        /// </summary>
        /// <returns>The data frame, null on end of stream</returns>
        public abstract DataFrame Read();

        /// <summary>
        /// Write a data frame to the underlying provider
        /// </summary>
        /// <param name="frame">The frame to write</param>
        public abstract void Write(DataFrame frame);

        /// <summary>
        /// Get the description
        /// </summary>
        public string Description { get; protected set; }

        /// <summary>
        /// Get or set the read timeout
        /// </summary>
        /// <exception cref="InvalidOperationException">Base version always throws InvalidOperationException</exception>
        public virtual int ReadTimeout
        {
            get { throw new InvalidOperationException(); }
            set { throw new InvalidOperationException(); }
        }

        /// <summary>
        /// Indicates if the data adapter can timeout
        /// </summary>
        public virtual bool CanTimeout
        {
            get { return false; }
        }

        /// <summary>
        /// Overriden ToString
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return Description;
        }

        /// <summary>
        /// Reconnect the data adapter
        /// </summary>
        /// <exception cref="NotSupportedException">Always thrown</exception>
        public virtual void Reconnect()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~BaseDataAdapter()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;

                // Ensure we capture exceptions, as this could be throw anywhere
                try
                {
                    OnDispose(false);
                }
                catch (Exception)
                {
                }
            }
        }

        /// <summary>
        /// Dispose method, called on Close, when finalizing and on Dispose
        /// </summary>
        /// <param name="disposing">True if called from Dispose or Close, false if called from finalizer</param>
        protected abstract void OnDispose(bool disposing);

        #endregion

        #region IDisposable Members

        /// <summary>
        /// IDispose method
        /// </summary>
        public void Dispose()
        {
            if (!_isDisposed)
            {
                _isDisposed = true;
                OnDispose(true);
                GC.SuppressFinalize(this);
            }
        }

        #endregion
    }
}
