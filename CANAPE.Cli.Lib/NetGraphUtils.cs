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
using CANAPE.Net.Utils;
using CANAPE.NodeFactories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CANAPE.Cli
{
    /// <summary>
    /// Simple utilities for netgraphs
    /// </summary>
    public static class NetGraphUtils
    {
        private static string FormatId(Guid id)
        {
            return String.Format("_{0}", id.ToString().Replace("-", "_"));
        }

        /// <summary>
        /// Convert a netgraph to a simple dot diagram
        /// </summary>
        /// <param name="netgraph">The netgraph to convert</param>
        /// <returns>The graph as a dot diagram</returns>
        public static string ToDot(NetGraphFactory netgraph)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendFormat("digraph netgraph {{").AppendLine();
            builder.AppendLine("rankdir=LR;");
            foreach (var node in netgraph.Nodes.Select(n => n.Factory))
            {
                List<string> attrs = new List<string>();
                if (!String.IsNullOrWhiteSpace(node.Label))
                {
                    attrs.Add(String.Format("label=\"{0}\"", node.Label));
                }

                if (node is ServerEndpointFactory)
                {
                    attrs.Add("ordering=out");
                    attrs.Add("rank=min");
                }
                else if (node is ClientEndpointFactory)
                {
                    attrs.Add("ordering=in");
                    attrs.Add("rank=max");
                }
                else
                {
                    attrs.Add("shape=box");
                }

                if (!node.Enabled)
                {
                    attrs.Add("style=dotted");
                }

                if (attrs.Count > 0)
                {
                    builder.AppendFormat("{0} [{1}];", FormatId(node.Id), String.Join(",", attrs)).AppendLine();
                }
            }

            foreach (var edge in netgraph.Lines)
            {
                builder.AppendFormat("{0} -> {1}", FormatId(edge.SourceNode), FormatId(edge.DestNode));
                if (!String.IsNullOrWhiteSpace(edge.PathName))
                {
                    builder.AppendFormat(" [label=\"{0}\"]", edge.PathName);
                }
                builder.AppendLine(";");
            }

            builder.AppendLine("}");

            return builder.ToString();
        }

        /// <summary>
        /// Get a default netgraph
        /// </summary>
        /// <returns>The default graph</returns>
        public static NetGraphFactory GetDefault()
        {
            return NetGraphBuilder.CreateDefaultProxyGraph("Default");
        }
    }
}
