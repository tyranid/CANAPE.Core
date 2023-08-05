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
using System;
using System.IO;
using System.Threading;

namespace CANAPE.Nodes
{
    /// <summary>
    /// Data adapter to interface with a data endpoint object
    /// </summary>
    public class DataEndpointAdapter : CoupledDataAdapter
    {
        IDataEndpoint _endpoint;
        Thread _thread;
        Logger _logger;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="server">Data endpoint object</param>
        /// <param name="logger">Logger object</param>
        public DataEndpointAdapter(IDataEndpoint server, Logger logger)
        {
            _endpoint = server;
            _logger = logger;
            this.Description = server.Description;

            _thread = new Thread(StartEndpoint);
            _thread.IsBackground = true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public override DataFrames.DataFrame Read()
        {
            lock (_thread)
            {
                if ((_thread.ThreadState & ThreadState.Unstarted) == ThreadState.Unstarted)
                {
                    _thread.Start();
                }
            }

            return base.Read();
        }

        private void StartEndpoint()
        {
            try
            {
                _endpoint.Logger = _logger;
                _endpoint.Run(Coupling);
            }
            catch (EndOfStreamException)
            {
                // End
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _logger.LogException(ex);
            }

            this.Coupling.Dispose();
        }
    }
}
