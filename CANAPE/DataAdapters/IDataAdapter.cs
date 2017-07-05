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
    /// Interface for a basic data adapter
    /// </summary>
    /// <remarks>
    /// This is the primitive for sourcing and sinking DataFrame objects, users of this interface should be completely
    /// agnostic to where that data comes from or goes to.
    /// </remarks>
    public interface IDataAdapter : IDisposable
    {
        /// <summary>
        /// Read a frame of data from the underlying provider
        /// </summary>
        /// <returns>The data frame, null on end of stream</returns>
        DataFrame Read();

        /// <summary>
        /// Write a frame of data to the underlying provider
        /// </summary>
        /// <param name="frame">The frame to write</param>
        void Write(DataFrame frame);

        /// <summary>
        /// Get a textual description of this adapter
        /// </summary>
        string Description { get; }

        /// <summary>
        /// Get or set the read timeout for this adapter (if unsupported it will throw InvalidOperationException)
        /// </summary>
        int ReadTimeout { get; set; }

        /// <summary>
        /// Gets whether this adapter can timeout
        /// </summary>
        bool CanTimeout { get; }

        /// <summary>
        /// Reconnect the data adapter
        /// </summary>
        void Reconnect();
    }
}
