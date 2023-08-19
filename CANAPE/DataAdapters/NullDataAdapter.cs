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
using System.Threading;

namespace CANAPE.DataAdapters
{
    /// <summary>
    /// A data adapter which is equivalent of /dev/null
    /// </summary>
    public class NullDataAdapter : BaseDataAdapter
    {
        private ManualResetEvent _exitEvent;

        /// <summary>
        /// Constructor
        /// </summary>
        public NullDataAdapter()
        {
            _exitEvent = new ManualResetEvent(false);
        }

        /// <summary>
        /// Blocks until close then returns null
        /// </summary>
        /// <returns>Always null</returns>
        public override DataFrame Read()
        {
            _exitEvent.WaitOne();

            return null;
        }

        /// <summary>
        /// Sinks data until receives null then closes adapter
        /// </summary>
        /// <param name="data"></param>
        public override void Write(DataFrame data)
        {
            if (data == null)
            {
                _exitEvent.Set();
            }
        }

        /// <summary>
        /// OnDispose method
        /// </summary>
        /// <param name="disposing"></param>
        protected override void OnDispose(bool disposing)
        {
            _exitEvent.Dispose();
        }
    }
}
