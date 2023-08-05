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
using System;
using System.Threading;

namespace CANAPE.DataAdapters
{
    /// <summary>
    /// A data adapter which has two IDataAdapter interfaces, one each side of a queue
    /// Can be used to traverse data between graphs
    /// </summary>
    public class CoupledDataAdapter : QueuedDataAdapter
    {
        private class QueuingDataAdapter : BaseDataAdapter
        {
            private CoupledDataAdapter _adapter;
            private int _readTimeout;

            public QueuingDataAdapter(CoupledDataAdapter adapter)
            {
                _adapter = adapter;
                _readTimeout = Timeout.Infinite;
            }

            public override DataFrames.DataFrame Read()
            {
                return _adapter.Dequeue(_readTimeout);
            }

            public override void Write(DataFrames.DataFrame data)
            {
                _adapter.Enqueue(data);
            }

            protected override void OnDispose(bool disposing)
            {
                _adapter.StopEnqueue();
            }

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

        /// <summary>
        /// The coupled adapter
        /// </summary>
        public IDataAdapter Coupling { get; private set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="token">A cancellation token to use</param>
        public CoupledDataAdapter(CancellationToken token)
            : base(token)
        {
            Coupling = new QueuingDataAdapter(this);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public CoupledDataAdapter()
            : this(CancellationToken.None)
        {
        }
    }
}
