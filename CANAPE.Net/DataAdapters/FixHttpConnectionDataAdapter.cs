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

namespace CANAPE.DataAdapters
{
    /// <summary>
    /// Class to fix a HTTP proxy connection
    /// </summary>
    public sealed class FixHttpConnectionDataAdapter : IDataAdapter
    {
        IDataAdapter _adapter;
        bool fixedConnection;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="adapter">The data adapter to wrap</param>        
        public FixHttpConnectionDataAdapter(IDataAdapter adapter)
        {
            _adapter = adapter;
            fixedConnection = false;
        }

        /// <summary>
        /// Read a data frame
        /// </summary>
        /// <returns>The data frame, null on end of file</returns>
        public DataFrame Read()
        {
            return _adapter.Read();
        }

        /// <summary>
        /// Write to the data adapter
        /// </summary>
        /// <param name="frame">The frame to write</param>
        public void Write(DataFrame frame)
        {
            if (!fixedConnection)
            {
                string s = BinaryEncoding.Instance.GetString(frame.ToArray());
                StringReader reader = new StringReader(s);
                string header = reader.ReadLine();

                while (header != null)
                {
                    if (header.StartsWith("Connection:"))
                    {
                        s = s.Replace(header, "Connection: close");
                        fixedConnection = true;
                        break;
                    }
                    else if (header.Length == 0)
                    {
                        fixedConnection = true;
                        break;
                    }

                    header = reader.ReadLine();
                }

                frame = s.ToDataFrame();
            }
            _adapter.Write(frame);
        }

        /// <summary>
        /// Get a string description
        /// </summary>
        public string Description { get { return _adapter.Description; } }

        /// <summary>
        /// Get or set the read timeout
        /// </summary>
        public int ReadTimeout
        {
            get { return _adapter.ReadTimeout; }
            set { _adapter.ReadTimeout = value; }
        }

        /// <summary>
        /// Dispose of the data adapter
        /// </summary>
        public void Dispose()
        {
            _adapter.Dispose();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Indicates if data adapter can timeout
        /// </summary>
        public bool CanTimeout
        {
            get { return _adapter.CanTimeout; }
        }

        /// <summary>
        /// Reconnect data adapter
        /// </summary>
        public void Reconnect()
        {
            _adapter.Reconnect();
        }
    }
}
