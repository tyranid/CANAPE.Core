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
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace CANAPE.Nodes
{
    /// <summary>
    /// Base class for implementations of pipeline nodes
    /// </summary>
    public abstract class BasePipelineNode : IDisposable
    {
        /// <summary>
        /// Class to hold a reference to an output node
        /// </summary>
        protected class OutputNode
        {
            /// <summary>
            /// The node object
            /// </summary>
            public BasePipelineNode Node { get; set; }

            /// <summary>
            /// The path name to reach the node
            /// </summary>
            public string PathName { get; set; }

            /// <summary>
            /// Indicates the path is weak and will not contribute to the shutdown of a node
            /// </summary>
            public bool WeakPath { get; set; }

            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="node"></param>
            /// <param name="pathName"></param>
            /// <param name="weak"></param>
            public OutputNode(BasePipelineNode node, string pathName, bool weak)
            {
                Node = node;
                PathName = pathName;
                WeakPath = weak;
            }
        }

        private bool _isDisposed;
        private Dictionary<string, dynamic> _props;
        private int _inputPacketCount;
        private int _outputPacketCount;
        private long _byteCount;
        private bool _breakpointHit;
        private int _isShutdown;

        /// <summary>
        /// A flag to indicate that the input mechanism should never write to the output
        /// if disabled, it should just discard it
        /// </summary>
        protected bool _noWriteOutput;

        /// <summary>
        /// The list of output nodes
        /// </summary>
        protected List<OutputNode> _output;

        /// <summary>
        /// The list of input nodes that are directly connected to this node
        /// </summary>
        protected HashSet<Guid> _shutdownInputs;

        /// <summary>
        /// Gets a list of output nodes
        /// </summary>
        public BasePipelineNode[] Outputs
        {
            get
            {
                lock (_output)
                {
                    return _output.Select(n => n.Node).ToArray();
                }
            }
        }

        internal void SetupShutdownOutputs()
        {
            foreach (OutputNode node in _output)
            {
                if (!node.WeakPath)
                {
                    node.Node._shutdownInputs.Add(this.Uuid);
                }
            }
        }

        /// <summary>
        /// Input method into pipeline node, specifying an input node
        /// </summary>        
        /// <param name="frame">The input frame, should never be null</param>
        public virtual void Input(DataFrame frame)
        {
            // If this is null then throw an exception as this isn't the way to shutdown the node anymore
            if (frame == null)
            {
                throw new ArgumentNullException("frame");
            }

            _inputPacketCount++;

            if (LogInput)
            {
                LogPacket(String.Format("{0} Input", Name), new ColorValue(255, 255, 255), frame, false);
            }

            if (Enabled && CanHandleFrame(frame))
            {
                OnInput(frame);
            }
            else if (!_noWriteOutput)
            {
                WriteOutput(frame);
            }
        }

        /// <summary>
        /// Overridable method to determine if this node can handle the frame
        /// If not then the frame will just be passed along to the next node
        /// The default will match against a list of filters
        /// </summary>
        /// <param name="frame">The input frame (will never be null)</param>
        /// <returns>True if the OnInput method of this node should be called. False will automatically 
        /// hand off to the output</returns>
        /// <remarks>Overriding this function and not calling the base implementation will prevent 
        /// the generic filters from operating</remarks>
        protected virtual bool CanHandleFrame(DataFrame frame)
        {
            return true;
        }

        /// <summary>
        /// Overridable method called when the pipeline is being shutdown
        /// </summary>
        /// <returns>Indicates whether to send null to output</returns>
        protected virtual bool OnShutdown()
        {
            return true;
        }

        /// <summary>
        /// Method to be implemented by derived type to handle receiving of input
        /// </summary>
        /// <param name="frame">The input frame</param>
        protected abstract void OnInput(DataFrame frame);

        /// <summary>
        /// Internal write function
        /// </summary>
        /// <param name="frame">The frame to write</param>
        /// <param name="nodes">The list of nodes to write to</param>
        private void WriteOutput(DataFrame frame, OutputNode[] nodes)
        {
            try
            {
                // Leave this like it is for legacy reasons.
                if (frame == null)
                {
                    foreach (OutputNode node in nodes)
                    {
                        node.Node.Shutdown(this);
                    }
                }
                else
                {
                    _outputPacketCount++;
                    _byteCount += frame.Length;
                    if (LogOutput)
                    {
                        LogPacket(String.Format("{0} Output", Name), new ColorValue(255, 255, 255), frame, false);
                    }

                    if (nodes.Length == 1)
                    {
                        // If we only have one output then don't need to clone
                        nodes[0].Node.Input(frame);
                    }
                    else
                    {
                        foreach (OutputNode node in nodes)
                        {
                            DataFrame newFrame = frame.Clone();

                            node.Node.Input(newFrame);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Back stop, do nothing but write to log
                LogException(ex);
            }
        }

        /// <summary>
        /// Write frame to default nodes only
        /// </summary>
        /// <param name="frame">The frame to write</param>
        public void WriteOutput(DataFrame frame)
        {
            WriteOutput(frame, false);
        }

        /// <summary>
        /// Write to the output a binary string
        /// </summary>
        /// <param name="s">The binary string to write</param>
        public void WriteOutput(string s)
        {
            WriteOutput(new StringDataFrame(s));
        }

        /// <summary>
        /// Write to the output a byte array
        /// </summary>
        /// <param name="ba">The byte aray</param>
        public void WriteOutput(byte[] ba)
        {
            WriteOutput(new ByteArrayDataFrame(ba));
        }

        /// <summary>
        /// Write frame to output nodes, including named or not
        /// </summary>
        /// <param name="frame">The frame to write</param>
        /// <param name="includeNamed">Whether to include named outputs or just default</param>
        public void WriteOutput(DataFrame frame, bool includeNamed)
        {
            OutputNode[] nodes;

            if (includeNamed)
            {
                lock (_output)
                {
                    nodes = _output.ToArray();
                }
            }
            else
            {
                lock (_output)
                {
                    nodes = _output.FindAll(n => String.IsNullOrWhiteSpace(n.PathName)).ToArray();
                }
            }

            WriteOutput(frame, nodes);
        }

        private OutputNode[] GetNodesByName(string pathName)
        {
            lock (_output)
            {
                return _output.FindAll(n => !String.IsNullOrWhiteSpace(n.PathName)
                    && n.PathName.Equals(pathName, StringComparison.OrdinalIgnoreCase)).ToArray(); ;
            }
        }

        private OutputNode[] GetNodesByNameExcluded(string[] pathNames)
        {
            List<OutputNode> nodes = new List<OutputNode>();

            lock (_output)
            {
                foreach (OutputNode node in _output)
                {
                    bool match = false;
                    foreach (string path in pathNames)
                    {
                        if (path.Equals(node.PathName, StringComparison.OrdinalIgnoreCase))
                        {
                            match = true;
                            break;
                        }
                    }

                    if (!match)
                    {
                        nodes.Add(node);
                    }
                }
            }

            return nodes.ToArray();
        }

        /// <summary>
        /// Write a frame to a specific named node in your output list
        /// </summary>
        /// <param name="frame">The frame to write</param>
        /// <param name="pathName">The path name to write to</param>
        public void WriteOutput(DataFrame frame, string pathName)
        {
            WriteOutput(frame, GetNodesByName(pathName));
        }

        /// <summary>
        /// Write a frame to the output nodes not specified in the list of paths
        /// </summary>
        /// <param name="frame">The frame to write</param>
        /// <param name="pathNames">The list of paths to NOT write to</param>
        public void WriteOutputExclude(DataFrame frame, params string[] pathNames)
        {
            WriteOutput(frame, GetNodesByNameExcluded(pathNames));
        }

        /// <summary>
        /// Determines if this node has at least one specific named output
        /// </summary>
        /// <param name="pathName">The path output name</param>
        /// <returns>True if it has the named output</returns>
        public bool HasOutput(string pathName)
        {
            return GetNodesByName(pathName).Length > 0;
        }

        /// <summary>
        /// Get or set name of the node
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Get or set the associated net graph
        /// </summary>
        public NetGraph Graph { get; set; }

        /// <summary>
        /// Get or set whether the node should be visible
        /// </summary>
        public bool Hidden { get; set; }

        /// <summary>
        /// Get or set whether this node is active
        /// </summary>
        public bool Enabled { get; set; }

        /// <summary>
        /// Get or set the UUID
        /// </summary>
        public Guid Uuid { get; set; }

        /// <summary>
        /// Indicates that the input of this node should be logged automatically
        /// </summary>
        public bool LogInput { get; set; }

        /// <summary>
        /// Indicates that the output of this node should be logged automatically
        /// </summary>
        public bool LogOutput { get; set; }

        /// <summary>
        /// An event which indicates that the node has been shutdown
        /// </summary>
        public event EventHandler NodeShutdown;

        /// <summary>
        /// Default constructor
        /// </summary>
        protected BasePipelineNode()
        {
            _props = new Dictionary<string, dynamic>();
            _output = new List<OutputNode>();
            _shutdownInputs = new HashSet<Guid>();
            Enabled = true;
            Name = "";
        }

        /// <summary>
        /// Add an output to the current node
        /// </summary>        
        /// <param name="node">The node to add</param>
        /// <param name="pathName">The name of the path from this node to the other</param>
        /// <param name="weak">Indicates the output is weak</param>
        public virtual void AddOutput(BasePipelineNode node, string pathName, bool weak)
        {
            lock (_output)
            {
                _output.Add(new OutputNode(node, pathName, weak));
            }
        }

        /// <summary>
        /// Overridden form of ToString
        /// </summary>
        /// <returns>The name of the node</returns>
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder(Name);

            if (Graph != null)
            {
                NetGraph graph = Graph;
                while (graph.Parent != null)
                {
                    builder.Insert(0, String.Format("{0}/", graph.Name));
                    graph = graph.Parent;
                }
            }

            return builder.ToString();
        }

        private void CompleteShutdown()
        {
            int isShutdown = Interlocked.Exchange(ref _isShutdown, 1);

            // Indicates this is the first time we have shutdown, signal the event
            if (isShutdown == 0)
            {
                if (NodeShutdown != null)
                {
                    NodeShutdown(this, new EventArgs());
                }
            }
        }

        /// <summary>
        /// Shutdown all output nodes
        /// </summary>
        protected virtual void ShutdownOutputs()
        {
            OutputNode[] nodes;

            lock (_output)
            {
                nodes = _output.ToArray();
            }

            try
            {
                foreach (OutputNode node in nodes)
                {
                    node.Node.Shutdown(this);
                }
            }
            finally
            {
                CompleteShutdown();
            }
        }

        /// <summary>
        /// Shutdown this node
        /// </summary>
        /// <param name="inputNode">The node which is requesting shutdown, if null then force</param>
        public virtual void Shutdown(BasePipelineNode inputNode)
        {
            bool doShutdown = false;

            lock (_shutdownInputs)
            {
                if (!IsShuttingdown)
                {
                    if (inputNode != null)
                    {
                        _shutdownInputs.Remove(inputNode.Uuid);
                        doShutdown = _shutdownInputs.Count == 0;
                    }
                    else
                    {
                        doShutdown = true;
                    }

                    IsShuttingdown = doShutdown;
                }
            }

            if (doShutdown)
            {
                // If true is returned we can safely pass along the shutdown
                if (OnShutdown())
                {
                    ShutdownOutputs();
                }
            }
        }

        /// <summary>
        /// Indicates the node is shutdown
        /// </summary>
        public bool IsShutdown
        {
            get
            {
                return _isShutdown != 0;
            }
        }

        /// <summary>
        /// Indicates the node is in the process of shutting down
        /// </summary>
        public bool IsShuttingdown { get; private set; }

        /// <summary>
        /// Finalizer
        /// </summary>
        ~BasePipelineNode()
        {
            Dispose(false);
        }

        /// <summary>
        /// Overridable method called no dispose
        /// </summary>
        /// <param name="disposing">True if disposing, otherwise finalizing</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_isDisposed)
            {
                lock (_output)
                {
                    _output.Clear();
                }
                _isDisposed = true;
            }
        }

        /// <summary>
        /// IDisposable.Dispose implementation
        /// </summary>
        public void Dispose()
        {
            try
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }
            finally
            {
                CompleteShutdown();
            }
        }

        /// <summary>
        /// Get the node properties
        /// </summary>
        public Dictionary<string, dynamic> Properties
        {
            get { return _props; }
        }

        /// <summary>
        /// Get a property of the node
        /// </summary>
        /// <param name="name">The name of the property</param>
        /// <returns>The value, null if it didn't exist</returns>
        public dynamic GetProperty(string name)
        {
            if (_props.ContainsKey(name))
            {
                return _props[name];
            }

            return null;
        }

        /// <summary>
        /// Set a property of the node
        /// </summary>
        /// <param name="name">The name of the property</param>
        /// <param name="value">The value, null to clear it</param>
        public void SetProperty(string name, dynamic value)
        {
            if (value == null)
            {
                _props.Remove(name);
            }
            else
            {
                _props[name] = value;
            }
        }

        /// <summary>
        /// Get the number of input packets this has handled
        /// </summary>
        public int InputPacketCount
        {
            get { return _inputPacketCount; }
        }

        /// <summary>
        /// Get the number of output packets this has sent
        /// </summary>
        public int OutputPacketCount
        {
            get { return _outputPacketCount; }
        }

        /// <summary>
        /// Get the number of bytes passed through this node
        /// </summary>
        public long ByteCount
        {
            get { return _byteCount; }
        }

        #region Logging Wrappers

        /// <summary>
        /// Log an entry
        /// </summary>
        /// <param name="entryType">The type to log</param>
        /// <param name="format">Format string</param>
        /// <param name="args">The args</param>
        public void Log(Logger.LogEntryType entryType, string format, params object[] args)
        {
            Graph.Logger.Log(entryType, Name, Uuid, format, args);
        }

        /// <summary>
        /// Log with an entry and only text
        /// </summary>
        /// <param name="entryType">The type to log</param>
        /// <param name="obj">The object to log</param>
        public void Log(Logger.LogEntryType entryType, object obj)
        {
            Graph.Logger.Log(entryType, Name, Uuid, obj);
        }

        /// <summary>
        /// Log verbose entry
        /// </summary>
        /// <param name="format"></param>
        /// <param name="args"></param>
        public void LogVerbose(string format, params object[] args)
        {
            Log(Logger.LogEntryType.Verbose, format, args);
        }

        /// <summary>
        /// Log verbose entry
        /// </summary>
        /// <param name="obj">The object to log</param>
        public void LogVerbose(object obj)
        {
            Log(Logger.LogEntryType.Verbose, obj);
        }

        /// <summary>
        /// Log info entry
        /// </summary>
        /// <param name="format">Format string</param>
        /// <param name="args">The args</param>
        public void LogInfo(string format, params object[] args)
        {
            Log(Logger.LogEntryType.Info, format, args);
        }

        /// <summary>
        /// Log info entry
        /// </summary>
        /// <param name="obj">The object to log</param>
        public void LogInfo(object obj)
        {
            Log(Logger.LogEntryType.Info, obj);
        }

        /// <summary>
        /// Log warning entry
        /// </summary>
        /// <param name="format">Format string</param>
        /// <param name="args">The args</param>
        public void LogWarning(string format, params object[] args)
        {
            Log(Logger.LogEntryType.Warning, format, args);
        }

        /// <summary>
        /// Log warning entry
        /// </summary>
        /// <param name="obj">The object to log</param>
        public void LogWarning(object obj)
        {
            Log(Logger.LogEntryType.Warning, obj);
        }

        /// <summary>
        /// Log error entry
        /// </summary>
        /// <param name="format">Format string</param>
        /// <param name="args">The args</param>
        public void LogError(string format, params object[] args)
        {
            Log(Logger.LogEntryType.Error, format, args);
        }

        /// <summary>
        /// Log error entry
        /// </summary>
        /// <param name="obj">The object to log</param>
        public void LogError(object obj)
        {
            Log(Logger.LogEntryType.Error, obj);
        }

        /// <summary>
        /// Log an exception
        /// </summary>
        /// <param name="type">Type of log entry</param>
        /// <param name="ex">The exception to log</param>
        public void LogException(Logger.LogEntryType type, Exception ex)
        {
            Graph.Logger.LogException(type, Name, Uuid, ex);
        }

        /// <summary>
        /// Log an exception
        /// </summary>
        /// <param name="ex">The exception to log</param>
        public void LogException(Exception ex)
        {
            Graph.Logger.LogException(Logger.LogEntryType.Error, Name, Uuid, ex);
        }
        #endregion

        #region Packet Logging Wrappers

        /// <summary>
        /// Wrapper method to log a packet
        /// </summary>
        /// <param name="tag">The logging tag</param>
        /// <param name="color">The logging colour</param>
        /// <param name="frame">The frame to log</param>
        /// <param name="logAsBytes">Indicates whether to log the packet as a byte array</param>
        protected void LogPacket(string tag, ColorValue color, DataFrame frame, bool logAsBytes)
        {
            Graph.DoLogPacket(tag, color, frame, false);
        }

        /// <summary>
        /// Log a packet from the graph with separated colour values
        /// </summary>
        /// <param name="tag">A textual tag for the frame</param>
        /// <param name="r">Red value</param>
        /// <param name="g">Green value</param>
        /// <param name="b">Blue value</param>
        /// <param name="frame">The frame to log, note this will be cloned to preserve its value</param>
        /// <param name="logAsBytes">Indicates whether the packet should be logged as a byte array</param>
        public void LogPacket(string tag, byte r, byte g, byte b, DataFrame frame, bool logAsBytes)
        {
            Graph.DoLogPacket(tag, r, g, b, frame, logAsBytes);
        }

        /// <summary>
        /// Edit a packet from the graph
        /// </summary>
        /// <param name="frame">The frame to edit</param>       
        /// <param name="color">The colour to show in an edit window (if applicable)</param>
        /// <param name="tag">The textual tag to show in an edit window (if applicable)</param>
        /// <returns>The returned frame, this may or may not be the same frame as sent</returns>        
        public DataFrame EditPacket(DataFrame frame, ColorValue color, string tag)
        {
            return Graph.DoEditPacket(frame, this, color, tag);
        }

        /// <summary>
        /// Edit a packet from the graph
        /// </summary>
        /// <param name="frame">The frame to edit</param>        
        public DataFrame EditPacket(DataFrame frame)
        {
            return Graph.DoEditPacket(frame, this, new ColorValue(255, 255, 255), String.Format("{0} Edit", Name));
        }

        #endregion

        #region Debugging Code

        /// <summary>
        /// Generate a breakpoint if debugger attached
        /// </summary>
        public void Break()
        {
            Break(true);
        }

        /// <summary>
        /// Generate a break point one time if debugger attached
        /// </summary>
        public void BreakOneTime()
        {
            BreakOneTime(true);
        }

        /// <summary>
        /// Generate a break point one time
        /// </summary>
        /// <param name="debuggerPresent">If true will check a debugger is present first</param>
        public void BreakOneTime(bool debuggerPresent)
        {
            if (_breakpointHit)
            {
                _breakpointHit = true;
                Break(true);
            }
        }

        /// <summary>
        /// Generate a break point
        /// </summary>
        /// <param name="debuggerPresent">If true will check a debugger is present first</param>
        public void Break(bool debuggerPresent)
        {
            if (!debuggerPresent || Debugger.IsAttached)
            {
                Debugger.Break();
            }
        }

        #endregion 
    }
}
