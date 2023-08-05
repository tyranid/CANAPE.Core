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

namespace CANAPE.Nodes
{
    /// <summary>
    /// Event arguments when a packet needs editing
    /// </summary>
    public class EditPacketEventArgs : EventArgs
    {
        /// <summary>
        /// The data frame to edit
        /// </summary>
        public DataFrame Frame { get; set; }

        /// <summary>
        /// The sending node
        /// </summary>
        public BasePipelineNode Sender { get; set; }

        /// <summary>
        /// The color to display in the edit window (if applicable)
        /// </summary>
        public ColorValue Color { get; set; }

        /// <summary>
        /// The textual tag to display in the edit window (if applicable)
        /// </summary>
        public string Tag { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="frame">The data frame to edit</param>
        /// <param name="sender">The sending node</param>
        /// <param name="color">The colour to show in an edit window</param>
        /// <param name="tag">The textual tag to show in an edit window</param>
        public EditPacketEventArgs(DataFrame frame,
                                   BasePipelineNode sender, ColorValue color, string tag)
        {
            Frame = frame;
            Sender = sender;
            Color = color;
            Tag = tag;
        }
    }

    /// <summary>
    /// A pipeline node which allows packets to be edited
    /// </summary>
    public class EditPacketPipelineNode : BasePipelineNode
    {
        private ColorValue _color;
        private string _tag;

        /// <summary>
        /// Constructor
        /// </summary>        
        /// <param name="color">The colour to show in an edit window</param>
        /// <param name="tag">The textual tag to show in an edit window</param>
        public EditPacketPipelineNode(ColorValue color, string tag)
        {
            _color = color;
            _tag = tag;
        }

        /// <summary>
        /// Method called when a new frame arraives
        /// </summary>
        /// <param name="frame">The frame</param>
        protected override void OnInput(DataFrame frame)
        {
            frame = EditPacket(frame, _color, _tag);

            if (frame != null)
            {
                WriteOutput(frame);
            }
        }
    }
}
