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
    /// A simple data adapter which allows you to specify its actions through delegates
    /// </summary>
    public class DelegateDataAdapter : IDataAdapter
    {
        private Action _onClose;
        private Func<DataFrame> _onRead;
        private Action<DataFrame> _onWrite;

        private static void DoNothing() { }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="onClose">Close delegate</param>
        /// <param name="onRead">Read delegate</param>
        /// <param name="onWrite">Write delegate</param>
        public DelegateDataAdapter(Action onClose, Action<DataFrame> onWrite, Func<DataFrame> onRead)
        {
            _onClose = onClose;
            _onRead = onRead;
            _onWrite = onWrite;
        }

        #region IDataAdapter Members

        /// <summary>
        /// Read method
        /// </summary>
        /// <returns>Returns read frame.</returns>
        public DataFrame Read()
        {
            if (_onRead != null)
            {
                return _onRead();
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Write method
        /// </summary>
        /// <param name="frame">The frame to write</param>
        public void Write(DataFrame frame)
        {
            _onWrite?.Invoke(frame);
        }

        /// <summary>
        /// Description
        /// </summary>
        public string Description
        {
            get { return "CloseDataAdapter"; }
        }

        /// <summary>
        /// Read timeout
        /// </summary>
        public int ReadTimeout
        {
            get
            {
                throw new NotImplementedException();
            }
            set
            {
                throw new NotImplementedException();
            }
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
        /// Can timeout
        /// </summary>
        public bool CanTimeout
        {
            get { return false; }
        }

        #endregion

        #region IDisposable Members

        /// <summary>
        /// Dispose method, does nothing
        /// </summary>
        public void Dispose()
        {
            _onClose?.Invoke();
        }

        #endregion
    }
}
