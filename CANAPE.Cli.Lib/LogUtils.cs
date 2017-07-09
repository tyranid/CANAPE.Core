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
using CANAPE.Utils;
using System.IO;

namespace CANAPE.Cli
{
    /// <summary>
    /// Utilities for packets.
    /// </summary>
    public static class LogUtils
    {
        /// <summary>
        /// Get a logger which logs to a text writer
        /// </summary>
        /// <param name="writer">A text writer object to use for output</param>
        /// <returns>The new logger</returns>
        public static Logger GetLogger(TextWriter writer)
        {
            Logger ret = new Logger();

            ret.LogEntryAdded += (sender, e) =>
                Ret_LogEntryAdded(writer, sender, e);

            return ret;
        }

        /// <summary>
        /// Get a logger which logs to a text writer
        /// </summary>
        /// <param name="file">A file to write the output to.</param>
        /// <returns>The new logger</returns>
        public static Logger GetLogger(string file)
        {
            return GetLogger(new StreamWriter(File.OpenWrite(file))
            {
                AutoFlush = true
            });
        }

        static void Ret_LogEntryAdded(TextWriter writer, object sender, Logger.LogEntryAddedEventArgs e)
        {
            string text = e.LogEntry.Text;
            if (e.LogEntry.ExceptionObject != null)
            {
                text = e.LogEntry.ExceptionObject.ToString();
            }

            writer.WriteLine("[{0}] {1} {2}: {3}\n", e.LogEntry.EntryType, e.LogEntry.Timestamp, e.LogEntry.SourceName, text);
        }

        /// <summary>
        /// Get a logger which logs to the console verbose logs
        /// </summary>
        /// <param name="writer">A text writer object to use for output</param>
        /// <returns>The new logger</returns>
        public static Logger GetVerboseLogger(TextWriter writer)
        {
            Logger l = GetLogger(writer);

            l.LogLevel = Logger.LogEntryType.All;

            return l;
        }
    }
}
