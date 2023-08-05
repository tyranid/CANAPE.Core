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
using System.Reflection;

namespace CANAPE.Utils
{
    /// <summary>
    /// Class to implement a simple logger
    /// </summary>
    public class Logger
    {
        /// <summary>
        /// Event log entry instance
        /// </summary>
        public class EventLogEntry
        {
            /// <summary>
            /// The time of the log entry
            /// </summary>
            public DateTime Timestamp { get; private set; }

            /// <summary>
            /// The type of the log entry
            /// </summary>
            public LogEntryType EntryType { get; private set; }

            /// <summary>
            /// The associated text
            /// </summary>
            public string Text { get; private set; }

            /// <summary>
            /// An associated exception object if available
            /// </summary>
            public Exception ExceptionObject { get; private set; }

            /// <summary>
            /// An associated source name
            /// </summary>
            public string SourceName { get; private set; }

            /// <summary>
            /// An associated source guid
            /// </summary>
            public Guid SourceGuid { get; private set; }

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="entryType">The log entry type</param>
            /// <param name="text">The associated text</param>
            /// <param name="sourceGuid">The guid of the source</param>
            /// <param name="sourceName">The name of the sourec</param>
            /// <param name="ex">An associated exception object if available</param>
            public EventLogEntry(LogEntryType entryType, string text, Exception ex, string sourceName, Guid sourceGuid)
            {
                Timestamp = DateTime.Now;
                EntryType = entryType;
                Text = text;
                ExceptionObject = ex;
                SourceName = sourceName;
                SourceGuid = sourceGuid;
            }
        }

        /// <summary>
        /// Log entry event args
        /// </summary>
        public class LogEntryAddedEventArgs : EventArgs
        {
            /// <summary>
            /// The log entry
            /// </summary>
            public EventLogEntry LogEntry { get; private set; }

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="entryType">The log entry type</param>
            /// <param name="text">The associated text</param>
            /// <param name="sourceGuid">The guid of the source</param>
            /// <param name="sourceName">The name of the sourec</param>
            /// <param name="ex">An associated exception object if available</param>
            public LogEntryAddedEventArgs(LogEntryType entryType, string text, Exception ex, string sourceName, Guid sourceGuid)
            {
                LogEntry = new EventLogEntry(entryType, text, ex, sourceName, sourceGuid);
            }
        }

        /// <summary>
        /// The log entry type
        /// </summary>
        [Flags]
        public enum LogEntryType
        {
            /// <summary>
            /// Log a verbose entry
            /// </summary>
            Verbose = 1,
            /// <summary>
            /// Log an information entry
            /// </summary>
            Info = 2,
            /// <summary>
            /// Log a warning entry
            /// </summary>
            Warning = 4,
            /// <summary>
            /// Log an error entry
            /// </summary>
            Error = 8,
            /// <summary>
            /// All the levels
            /// </summary>
            All = Verbose | Info | Warning | Error
        }

        /// <summary>
        /// Specify the level of the logging
        /// </summary>
        public LogEntryType LogLevel { get; set; }

        /// <summary>
        /// Event when log entry received
        /// </summary>
        public event EventHandler<LogEntryAddedEventArgs> LogEntryAdded;

        /// <summary>
        /// Log a formatted entry
        /// </summary>
        /// <param name="entryType">The type to log</param>
        /// <param name="sourceName">The name of the source of the log</param>
        /// <param name="sourceGuid">The guid of the source of the log</param>
        /// <param name="format">The format string</param>
        /// <param name="args">Format arguments</param>
        public void Log(LogEntryType entryType, string sourceName, Guid sourceGuid, string format, params object[] args)
        {
            if (LogEntryAdded != null)
            {
                if ((LogLevel & entryType) == entryType)
                {
                    LogEntryAdded.Invoke(this, new LogEntryAddedEventArgs(entryType, String.Format(format, args), null, sourceName, sourceGuid));
                }
            }
        }

        /// <summary>
        /// Log a formatted entry 
        /// </summary>
        /// <param name="entryType">The type to log</param>
        /// <param name="format">Format string</param>
        /// <param name="args">The args</param>
        public void Log(LogEntryType entryType, string format, params object[] args)
        {
            Log(entryType, "Service", Guid.Empty, format, args);
        }

        /// <summary>
        /// Log with an entry and only text
        /// </summary>
        /// <param name="entryType">The type to log</param>
        /// <param name="sourceName">The name of the source of the log</param>
        /// <param name="sourceGuid">The guid of the source of the log</param>
        /// <param name="text">The text string</param>
        public void Log(LogEntryType entryType, string sourceName, Guid sourceGuid, string text)
        {
            if ((LogEntryAdded != null) && (text != null))
            {
                if ((LogLevel & entryType) == entryType)
                {
                    LogEntryAdded.Invoke(this, new LogEntryAddedEventArgs(entryType, text, null, sourceName ?? "Unknown", sourceGuid));
                }
            }
        }

        /// <summary>
        /// Log with an entry and only text
        /// </summary>
        /// <param name="entryType">The type to log</param>
        /// <param name="text">The text to log</param>
        public void Log(LogEntryType entryType, string text)
        {
            Log(entryType, "Service", Guid.Empty, text);
        }

        /// <summary>
        /// Log with an entry and an object
        /// </summary>
        /// <param name="entryType">The type to log</param>
        /// <param name="obj">The object to log</param>
        public void Log(LogEntryType entryType, object obj)
        {
            Log(entryType, obj != null ? obj.ToString() : "null");
        }

        /// <summary>
        /// Log with an entry and an object
        /// </summary>
        /// <param name="entryType">The type to log</param>
        /// <param name="sourceName">The name of the source of the log</param>
        /// <param name="sourceGuid">The guid of the source of the log</param>
        /// <param name="obj">The object to log</param>
        public void Log(LogEntryType entryType, string sourceName, Guid sourceGuid, object obj)
        {
            Log(entryType, sourceName, sourceGuid, obj != null ? obj.ToString() : "null");
        }

        /// <summary>
        /// Log verbose entry
        /// </summary>
        /// <param name="format">Format string</param>
        /// <param name="args">The args</param>
        public void LogVerbose(string format, params object[] args)
        {
            Log(LogEntryType.Verbose, format, args);
        }

        /// <summary>
        /// Log verbose entry
        /// </summary>
        /// <param name="text">The text to log</param>
        public void LogVerbose(string text)
        {
            Log(LogEntryType.Verbose, text);
        }

        /// <summary>
        /// Log verbose entry
        /// </summary>
        /// <param name="obj">The obj to log</param>
        public void LogVerbose(object obj)
        {
            Log(LogEntryType.Verbose, obj);
        }

        /// <summary>
        /// Log info entry
        /// </summary>
        /// <param name="format">Format string</param>
        /// <param name="args">The args</param>
        public void LogInfo(string format, params object[] args)
        {
            Log(LogEntryType.Info, format, args);
        }

        /// <summary>
        /// Log info entry
        /// </summary>
        /// <param name="text">The text to log</param>
        public void LogInfo(string text)
        {
            Log(LogEntryType.Info, text);
        }

        /// <summary>
        /// Log info entry
        /// </summary>
        /// <param name="obj">The object to log</param>
        public void LogInfo(object obj)
        {
            Log(LogEntryType.Info, obj);
        }

        /// <summary>
        /// Log warning entry
        /// </summary>
        /// <param name="format">Format string</param>
        /// <param name="args">The args</param>
        public void LogWarning(string format, params object[] args)
        {
            Log(LogEntryType.Warning, format, args);
        }

        /// <summary>
        /// Log warning entry
        /// </summary>
        /// <param name="text">The text to log</param>
        public void LogWarning(string text)
        {
            Log(LogEntryType.Warning, text);
        }

        /// <summary>
        /// Log warning entry
        /// </summary>
        /// <param name="obj">The object to log</param>
        public void LogWarning(object obj)
        {
            Log(LogEntryType.Warning, obj);
        }

        /// <summary>
        /// Log error entry
        /// </summary>
        /// <param name="format">Format string</param>
        /// <param name="args">The args</param>
        public void LogError(string format, params object[] args)
        {
            Log(LogEntryType.Error, format, args);
        }

        /// <summary>
        /// Log error entry
        /// </summary>
        /// <param name="text">The text to log</param>
        public void LogError(string text)
        {
            Log(LogEntryType.Error, text);
        }

        /// <summary>
        /// Log error entry
        /// </summary>
        /// <param name="obj">The object to log</param>
        public void LogError(object obj)
        {
            Log(LogEntryType.Error, obj);
        }

        /// <summary>
        /// Log an exception
        /// </summary>
        /// <param name="type">Type of log entry</param>
        /// <param name="ex">The exception to log</param>
        public void LogException(LogEntryType type, Exception ex)
        {
            LogException(type, "Service", Guid.Empty, ex);
        }

        /// <summary>
        /// Log an exception
        /// </summary>
        /// <param name="type">Type of log entry</param>
        /// <param name="sourceGuid">Guid of the source</param>
        /// <param name="sourceName">Name of the source</param>
        /// <param name="ex">The exception to log</param>
        public void LogException(LogEntryType type, string sourceName, Guid sourceGuid, Exception ex)
        {
            if (LogEntryAdded != null)
            {
                if ((LogLevel & type) == type)
                {
                    string message = ex.Message;

                    // Unwrap a few common wrapped messages
                    if (ex is TargetInvocationException)
                    {
                        if (ex.InnerException != null)
                        {
                            message = ex.InnerException.Message;
                        }
                    }

                    LogEntryAdded.Invoke(this, new LogEntryAddedEventArgs(type, message, ex, sourceName, sourceGuid));
                }
            }
        }

        /// <summary>
        /// Log an exception as an error
        /// </summary>
        /// <param name="ex">The exception to log</param>
        public void LogException(Exception ex)
        {
            LogException(LogEntryType.Error, ex);
        }

        /// <summary>
        /// Default constructor
        /// </summary>
        public Logger()
        {
            LogLevel = LogEntryType.Info | LogEntryType.Warning | LogEntryType.Error;
        }

        private static Logger _system_logger;

        /// <summary>
        /// Get a default logger which outputs to stdout
        /// </summary>
        /// <returns></returns>
        public static Logger SystemLogger
        {
            get
            {
                if (_system_logger != null)
                {
                    return _system_logger;
                }

                Logger ret = new Logger();
                ret.LogEntryAdded += new EventHandler<LogEntryAddedEventArgs>(ret_LogEntryAdded);
                return ret;
            }

            set
            {
                _system_logger = value;
            }
        }

        /// <summary>
        /// Handler for system logger
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private static void ret_LogEntryAdded(object sender, LogEntryAddedEventArgs e)
        {
        }
    }
}
