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
using CANAPE.Utils;

namespace CANAPE.Nodes
{
    /// <summary>
    /// The interface to implement a server of data, 
    /// be that a client or a server in the traditional sense
    /// </summary>
    public interface IDataEndpoint
    {
        /// <summary>
        /// Run the endpoint
        /// </summary>
        /// <param name="adapter">Adapter</param>
        void Run(IDataAdapter adapter);

        /// <summary>
        /// Get a descriptive name for the endpoint
        /// </summary>
        string Description { get; }

        /// <summary>
        /// Logger for endpoint.
        /// </summary>
        Logger Logger { get; set; }

        /// <summary>
        /// Meta
        /// </summary>
        MetaDictionary Meta { get; set; }

        /// <summary>
        /// Global meta
        /// </summary>
        MetaDictionary GlobalMeta { get; set; }
    }
}
