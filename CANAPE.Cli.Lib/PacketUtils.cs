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
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

namespace CANAPE.Cli
{
    /// <summary>
    /// Utilities for packets.
    /// </summary>
    public static class PacketUtils
    {
        /// <summary>
        /// Write a hexdump of a byte array to a string
        /// </summary>        
        /// <param name="rowLength">Length of a row</param>
        /// <param name="data">Data length</param>
        /// <returns>The hex dump string</returns>
        private static string BuildHexDump(int rowLength, byte[] data)
        {
            StringBuilder builder = new StringBuilder();

            BuildHexDump(builder, rowLength, data);

            return builder.ToString();
        }


        /// <summary>
        /// Print a row of hex to the string builder
        /// </summary>
        /// <param name="builder">The string builder to write to</param>
        /// <param name="rowLength">Length of the row</param>
        /// <param name="data">The data array</param>
        /// <param name="offset">Offset in the array</param>
        /// <param name="len">Length of the current row</param>
        private static void PrintRow(StringBuilder builder, int rowLength, byte[] data, int offset, int len)
        {
            builder.AppendFormat("{0:X08}: ", offset);
            for (int i = 0; i < rowLength; i++)
            {
                if (i < len)
                {
                    builder.AppendFormat("{0:X02} ", data[i + offset]);
                }
                else
                {
                    builder.Append("   ");
                }
            }

            builder.Append("- ");

            for (int i = 0; i < rowLength; i++)
            {
                if (i < len)
                {
                    char val = (char)data[i + offset];

                    if ((val >= 32) && (val < 127))
                    {
                        builder.AppendFormat("{0}", val);
                    }
                    else
                    {
                        builder.Append(".");
                    }
                }
                else
                {
                    builder.Append(" ");
                }
            }

            builder.AppendLine();
        }


        /// <summary>
        /// Write a hexdump of a byte array to a string builder
        /// </summary>
        /// <param name="builder">The string builder</param>
        /// <param name="rowLength">Length of a row</param>
        /// <param name="data">Data length</param>
        private static void BuildHexDump(StringBuilder builder, int rowLength, byte[] data)
        {
            int rows = data.Length / rowLength;
            int res = data.Length % rowLength;

            builder.Append("        : ");

            for (int i = 0; i < rowLength; i++)
            {
                builder.AppendFormat("{0:X02} ", i & 0xF);
            }

            builder.Append("- ");

            for (int i = 0; i < rowLength; i++)
            {
                builder.AppendFormat("{0:X}", i & 0xF);
            }
            builder.AppendLine();
            builder.Append("--------:-");
            for (int i = 0; i < rowLength; i++)
            {
                builder.Append("---");
            }
            builder.Append("--");
            for (int i = 0; i < rowLength; i++)
            {
                builder.Append("-");
            }
            builder.AppendLine();

            for (int i = 0; i < rows; i++)
            {
                PrintRow(builder, rowLength, data, i * rowLength, rowLength);
            }

            if (res > 0)
            {
                PrintRow(builder, rowLength, data, rows * rowLength, res);
            }
        }


        private static string GetHeader(LogPacket p)
        {
            return String.Format("Time {0} - Tag '{1}' - Network '{2}'",
                    p.Timestamp.ToString(), p.Tag, p.Network);
        }

        /// <summary>
        /// Convert a packet to a hex string format
        /// </summary>
        /// <param name="p">The packet to convert</param>
        /// <returns>The converted string</returns>
        private static string ConvertBinaryPacketToString(DataFrame p)
        {
            using (TextWriter writer = new StringWriter())
            {
                writer.WriteLine(BuildHexDump(16, p.ToArray()));
                return writer.ToString();
            }
        }

        /// <summary>
        /// Convert a packet to a text string format
        /// </summary>
        /// <param name="p">The packet to convert</param>
        /// <returns>The converted string</returns>
        private static string ConvertTextPacketToString(DataFrame p)
        {
            using (TextWriter writer = new StringWriter())
            {
                writer.WriteLine(p.ToDataString());

                return writer.ToString();
            }
        }

        public static string ConvertPacketToString(DataFrame p)
        {
            if (p is StringDataFrame)
            {
                return ConvertTextPacketToString(p);
            }
            else
            {
                return ConvertBinaryPacketToString(p);
            }
        }

        private static ColorValue PickContrastingColor(ColorValue color)
        {
            int y = (int)(0.2126 * color.R + 0.7152 * color.G + 0.0722 * color.B);
            if (y < 100)
            {
                return ColorValue.White;
            }
            else
            {
                return ColorValue.Black;
            }
        }

        private static string FormatColor(ColorValue color, bool background)
        {
            return String.Format("\x1b[{0};2;{1};{2};{3}m", background ? 48 : 38, color.R, color.G, color.B);
        }

        private static string GetStartPacketColor(LogPacket packet, bool enable_color)
        {
            if (!enable_color)
            {
                return "";
            }

            ColorValue color = packet.Color;

            return String.Format("{0}{1}", FormatColor(color, true), FormatColor(PickContrastingColor(color), false));
        }

        private static string GetEndPacketColor(bool enable_color)
        {
            if (!enable_color)
            {
                return "";
            }

            return "\x1b[0m";
        }

        public static string ConvertPacketToString(LogPacket p, bool enable_color)
        {
            using (TextWriter writer = new StringWriter())
            {
                writer.WriteLine(GetHeader(p));
                writer.Write(GetStartPacketColor(p, enable_color));
                writer.Write(ConvertPacketToString(p.Frame));
                writer.WriteLine(GetEndPacketColor(enable_color));
                return writer.ToString();
            }
        }

        public static string ConvertPacketsToString(IEnumerable<LogPacket> ps, bool enable_color)
        {
            using (TextWriter writer = new StringWriter())
            {
                int count = 0;

                foreach (LogPacket p in ps)
                {
                    writer.Write(ConvertPacketToString(p, enable_color));
                    count++;
                }

                return writer.ToString();
            }
        }

        private static void WriteBinaryPacketAsHtml(XmlWriter writer, DataFrame frame, ColorValue c)
        {
            writer.WriteStartElement("pre");
            writer.WriteAttributeString("style", String.Format("background-color:#{0:X02}{1:X02}{2:X02}", c.R, c.G, c.B));
            writer.WriteString(BuildHexDump(16, frame.ToArray()));
            writer.WriteEndElement();
        }

        private static void WriteTextPacketAsHtml(XmlWriter writer, DataFrame frame, ColorValue c)
        {
            writer.WriteStartElement("pre");
            writer.WriteAttributeString("style", String.Format("background-color:#{0:X02}{1:X02}{2:X02}", c.R, c.G, c.B));
            writer.WriteString(frame.ToDataString());
            writer.WriteEndElement();
        }

        private static void ConvertPacketsToHtml(TextWriter textWriter, IEnumerable<LogPacket> ps, bool forcebin)
        {
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            settings.OmitXmlDeclaration = true;

            using (XmlWriter writer = XmlWriter.Create(textWriter, settings))
            {
                int count = 0;

                writer.WriteStartElement("html");
                writer.WriteStartElement("head");
                writer.WriteElementString("title", "Packet Log");
                writer.WriteEndElement();
                writer.WriteStartElement("body");

                foreach (LogPacket p in ps)
                {
                    DataFrame f = p.Frame;
                    writer.WriteElementString("h2", String.Format("Time {0} - Tag '{1}' - Network '{2}'",
                        p.Timestamp.ToString(), p.Tag, p.Network));
                    ColorValue c = p.Color;
                    count++;

                    if (f is ByteArrayDataFrame || forcebin)
                    {
                        WriteBinaryPacketAsHtml(writer, f, c);
                    }
                    else
                    {
                        WriteTextPacketAsHtml(writer, f, c);
                    }
                }

                writer.WriteEndElement();
                writer.WriteEndElement();
            }
        }

        public static string ConvertPacketsToHtml(IEnumerable<LogPacket> ps)
        {
            using (TextWriter textWriter = new StringWriter())
            {
                ConvertPacketsToHtml(textWriter, ps, false);

                return textWriter.ToString();
            }
        }

        public static string ConvertPacketToHtml(LogPacket p)
        {
            return ConvertPacketsToHtml(new LogPacket[] { p });
        }
    }
}
