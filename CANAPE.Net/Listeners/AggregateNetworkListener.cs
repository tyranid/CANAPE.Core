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
using System.Collections.Generic;

namespace CANAPE.Net.Listeners
{
    /// <summary>
    /// A network listener which can aggregate 2 different listeners together
    /// </summary>
    public sealed class AggregateNetworkListener : INetworkListener
    {
        INetworkListener _left;
        INetworkListener _right;

        /// <summary>
        /// Get the left listener
        /// </summary>
        public INetworkListener Left
        {
            get { return _left; }
        }

        /// <summary>
        /// Get the right listener
        /// </summary>
        public INetworkListener Right
        {
            get { return _right; }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="left">The left listener</param>
        /// <param name="right">The right listener</param>
        public AggregateNetworkListener(INetworkListener left, INetworkListener right)
        {
            _left = left;
            _right = right;
        }

        /// <summary>
        /// Start the listener
        /// </summary>
        public void Start()
        {
            _left.Start();
            _right.Start();
        }

        /// <summary>
        /// Stop the listener
        /// </summary>
        public void Stop()
        {
            _left.Stop();
            _right.Stop();
        }

        /// <summary>
        /// Client connected event
        /// </summary>
        public event EventHandler<ClientConnectedEventArgs> ClientConnected
        {
            add
            {
                _left.ClientConnected += value;
                _right.ClientConnected += value;
            }
            remove
            {
                _left.ClientConnected -= value;
                _right.ClientConnected -= value;
            }
        }

        /// <summary>
        /// Dispose method
        /// </summary>
        public void Dispose()
        {
            _left.Dispose();
            _right.Dispose();
        }

        private static void AddListener(List<string> builder, INetworkListener listener)
        {
            if (listener is AggregateNetworkListener)
            {
                AddAggregateListener(builder, (AggregateNetworkListener)listener);
            }
            else
            {
                builder.Add(listener.ToString());
            }
        }

        private static void AddAggregateListener(List<string> builder, AggregateNetworkListener listener)
        {
            AddListener(builder, listener._left);
            AddListener(builder, listener._right);
        }

        /// <summary>
        /// ToString implementation
        /// </summary>
        /// <returns>Return the listener information</returns>
        public override string ToString()
        {
            List<string> builder = new List<string>();

            AddAggregateListener(builder, this);

            return String.Join(",", builder);
        }
    }
}
