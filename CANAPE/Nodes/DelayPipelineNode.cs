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

namespace CANAPE.Nodes
{
    /// <summary>
    /// A pipeline node with a built-in delay
    /// </summary>
    public class DelayPipelineNode : BaseDecoupledPipelineNode
    {
        /// <summary>
        /// Specify a packet delay in ms
        /// </summary>
        public int PacketDelayMs { get; set; }

        /// <summary>
        /// Called when a new frame arrives (just forwards)
        /// </summary>
        /// <param name="frame"></param>
        protected override void OnInput(DataFrame frame)
        {
            if (PacketDelayMs > 0)
            {
                Thread.Sleep(PacketDelayMs);
            }

            WriteOutput(frame);
        }
    }
}
