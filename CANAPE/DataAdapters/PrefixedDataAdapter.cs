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

namespace CANAPE.DataAdapters
{
    /// <summary>
    /// Implement a data adapter which wraps another but prefixes the first read with a block of data
    /// </summary>
    public sealed class PrefixedDataAdapter : IDataAdapter
    {
        IDataAdapter _adapter;
        byte[] _data;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="adapter">The data adapter to wrap</param>
        /// <param name="data">The prefix data to send</param>
        public PrefixedDataAdapter(IDataAdapter adapter, byte[] data)
        {
            _adapter = adapter;
            _data = data;
        }

        /// <summary>
        /// Read a data frame
        /// </summary>
        /// <returns>The data frame, null on end of file</returns>
        public DataFrame Read()
        {
            if (_data != null)
            {
                byte[] ret = _data;
                _data = null;

                return ret.ToDataFrame();
            }
            else
            {
                return _adapter.Read();
            }
        }

        /// <summary>
        /// Write to the data adapter
        /// </summary>
        /// <param name="frame">The frame to write</param>
        public void Write(DataFrame frame)
        {
            _adapter.Write(frame);
        }

        /// <summary>
        /// Get a string description
        /// </summary>
        public string Description { get { return _adapter.Description; } }

        /// <summary>
        /// Dispose of the data adapter
        /// </summary>
        public void Dispose()
        {
            _adapter.Dispose();
        }

        /// <summary>
        /// Get or set the read timeout
        /// </summary>
        public int ReadTimeout
        {
            get { return _adapter.ReadTimeout; }
            set { _adapter.ReadTimeout = value; }
        }

        /// <summary>
        /// Indicates if data adapter can timeout
        /// </summary>
        public bool CanTimeout
        {
            get { return _adapter.CanTimeout; }
        }

        /// <summary>
        /// Reconnect the data adapter
        /// </summary>
        public void Reconnect()
        {
            _adapter.Reconnect();
        }
    }
}
