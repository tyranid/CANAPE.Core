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
using CANAPE.DataAdapters;
using System;

namespace CANAPE.Net.DataAdapters
{
    /// <summary>
    /// A data adapter which is backed by a bound connection (e.g. a listening TCP socket)
    /// </summary>
    public abstract class BoundDataAdapter : BaseDataAdapter
    {
        private IDataAdapter _boundAdapter;

        /// <summary>
        /// Do connection
        /// </summary>
        /// <param name="timeout">Timeout in seconds</param>
        /// <returns>The conneced adapter</returns>
        protected abstract IDataAdapter DoConnect(int timeout);

        /// <summary>
        /// Indicate whether adapter is connected
        /// </summary>
        public bool IsConnected { get { return _boundAdapter != null; } }

        /// <summary>
        /// Connect the adapter
        /// </summary>
        /// <param name="timeout">Timeout in seconds</param>
        public void Connect(int timeout)
        {
            _boundAdapter = DoConnect(timeout);
        }

        /// <summary>
        /// Read a data frame
        /// </summary>
        /// <returns>The frame, null on eos</returns>
        public override DataFrames.DataFrame Read()
        {
            if (_boundAdapter != null)
            {
                return _boundAdapter.Read();
            }
            else
            {
                throw new InvalidOperationException();
            }
        }

        /// <summary>
        /// Write data adapter
        /// </summary>
        /// <param name="data">The frame to write</param>
        public override void Write(DataFrames.DataFrame data)
        {
            if (_boundAdapter != null)
            {
                _boundAdapter.Write(data);
            }
            else
            {
                throw new InvalidOperationException();
            }
        }

        /// <summary>
        /// On dispose
        /// </summary>
        /// <param name="disposing">True disposing</param>
        protected override void OnDispose(bool disposing)
        {
            if (_boundAdapter != null)
            {
                _boundAdapter.Dispose();
            }
        }
    }
}
