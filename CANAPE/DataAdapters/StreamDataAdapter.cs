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
    /// Data adapter for a stream object
    /// </summary>
    public class StreamDataAdapter : BaseDataAdapter
    {
        const int MAX_BUFFER_SIZE = 8192;
        private Stream _stream;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="stream">The stream to read and write to</param>
        public StreamDataAdapter(Stream stream) : this(stream, null)
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="stream">The stream to wrap the data adapter around</param>
        /// <param name="description">A textual description to identify the adapter</param>
        public StreamDataAdapter(Stream stream, string description)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            _stream = stream;

            if (_stream is DataAdapterToStream)
            {
                Description = ((DataAdapterToStream)stream).Description;
            }
            else
            {
                Description = description;
            }
        }

        /// <summary>
        /// Perform a read
        /// </summary>
        /// <returns>The data frame</returns>
        public override DataFrame Read()
        {
            DataFrame ret = null;

            try
            {
                byte[] buf = new byte[MAX_BUFFER_SIZE];

                int len = _stream.Read(buf, 0, buf.Length);
                if (len > 0)
                {
                    Array.Resize<byte>(ref buf, len);

                    ret = new ByteArrayDataFrame(buf);
                }
            }
            catch (Exception)
            {
                ret = null;
            }

            return ret;
        }

        /// <summary>
        /// Perform write
        /// </summary>
        /// <param name="frame"></param>
        public override void Write(DataFrame frame)
        {
            try
            {
                byte[] data = frame.ToArray();
                _stream.Write(data, 0, data.Length);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.ToString());
            }
        }

        /// <summary>
        /// Get or set the read timeout
        /// </summary>
        public override int ReadTimeout
        {
            get
            {
                return _stream.ReadTimeout;
            }
            set
            {
                _stream.ReadTimeout = value;
            }
        }

        /// <summary>
        /// Perform close
        /// </summary>
        protected override void OnDispose(bool disposing)
        {
            try
            {
                _stream.Dispose();
            }
            catch (Exception ex)
            {
                Logger.SystemLogger.LogException(ex);
            }
        }
    }
}
