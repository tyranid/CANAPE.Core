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
using CANAPE.Nodes;
using CANAPE.Utils;

namespace CANAPE.Net.Templates.Factories
{
    /// <summary>
    /// Class for data end point with configuration.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <typeparam name="C"></typeparam>
    public sealed class DataEndpointFactory<T, C>
        where T : IDataEndpoint, IPersistNode, new() where C : new()
    {
        /// <summary>
        /// Constructor
        /// </summary>
        public DataEndpointFactory()
        {
            Config = new C();
        }

        /// <summary>
        /// Configuration.
        /// </summary>
        public C Config { get; private set; }

        /// <summary>
        /// Create the data endpoint
        /// </summary>
        /// <param name="logger">Logger</param>
        /// <param name="meta">Metadata</param>
        /// <param name="globalMeta">Global metadata</param>
        /// <returns></returns>
        public IDataEndpoint Create(Logger logger, MetaDictionary meta, MetaDictionary globalMeta)
        {
            T server = new T()
            {
                Logger = logger,
                Meta = meta,
                GlobalMeta = globalMeta
            };
            server.SetState(Config, logger);
            return server;
        }

        /// <summary>
        /// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:CANAPE.Net.Templates.Factories.DataEndpointFactory`2"/>.
        /// </summary>
        /// <returns>A <see cref="T:System.String"/> that represents the current <see cref="T:CANAPE.Net.Templates.Factories.DataEndpointFactory`2"/>.</returns>
        public override string ToString()
        {
            return typeof(T).Name;
        }
    }
}
