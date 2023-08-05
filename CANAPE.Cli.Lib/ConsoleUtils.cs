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
using System.Runtime.InteropServices;

namespace CANAPE.Cli
{
    /// <summary>
    /// Utilities for the console 
    /// </summary>
    public static class ConsoleUtils
    {
        private static Dictionary<ColorValue, ConsoleColor> _color_map
            = new Dictionary<ColorValue, ConsoleColor>();

        const int ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;

        const int STD_OUTPUT_HANDLE = -11;
        const int STD_ERROR_HANDLE = -12;

        [DllImport("Kernel32.dll")]
        private static extern IntPtr GetStdHandle(
            int nStdHandle
        );

        [DllImport("Kernel32.dll")]
        private static extern bool SetConsoleMode(
            IntPtr hConsoleHandle,
            int dwMode
        );

        [DllImport("Kernel32.dll")]
        private static extern bool GetConsoleMode(
            IntPtr hConsoleHandle,
            out int dwMode
        );

        internal static bool EnableAnsiColors()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                // Assume Linux/macOS always support color output.
                return true;
            }

            IntPtr handle = GetStdHandle(STD_OUTPUT_HANDLE);
            if (handle == new IntPtr(-1))
            {
                return false;
            }

            int mode = 0;
            if (!GetConsoleMode(handle, out mode))
            {
                return false;
            }

            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if (!SetConsoleMode(handle, mode))
            {
                return false;
            }

            return true;
        }

        private static bool _supports_ansi_color = EnableAnsiColors();

        /// <summary>
        /// Get or set output color mode.
        /// </summary>
        public static bool EnableColor
        {
            get; set;
        }

        private static bool GetEffectiveColorMode()
        {
            return _supports_ansi_color && EnableColor;
        }

        public static void WritePacket(LogPacket packet)
        {
            Console.Out.WriteLine(PacketUtils.ConvertPacketToString(packet, GetEffectiveColorMode()));
        }

        public static void WritePackets(IEnumerable<LogPacket> packets)
        {
            foreach (LogPacket packet in packets)
            {
                WritePacket(packet);
            }
        }

        public static void WritePacket(DataFrame frame)
        {
            Console.Out.WriteLine(PacketUtils.ConvertPacketToString(frame));
        }

        public static void WritePackets(IEnumerable<DataFrame> packets)
        {
            foreach (DataFrame packet in packets)
            {
                WritePacket(packet);
            }
        }
    }
}
