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
namespace CANAPE.Nodes
{
    /// <summary>
    /// A base implementation for persisting a node
    /// </summary>
    public abstract class PersistNodeImpl<T, R> : IPersistNode where R : class where T : class, R, new()
    {
        /// <summary>
        /// Base constructor
        /// </summary>
        protected PersistNodeImpl()
        {
            _config = new T();
        }

        #region IPersistNode Members

        /// <summary>
        /// Config object
        /// </summary>
        private T _config;

        /// <summary>
        /// The current config
        /// </summary>
        public R Config
        {
            get { return _config; }
        }

        /// <summary>
        /// Overridable method to validate config, should throw an ArgumentException if invalid
        /// </summary>
        /// <param name="config">The config</param>
        protected virtual void ValidateConfig(T config)
        {
            // Do nothing
        }

        /// <summary>
        /// Get the node state
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public object GetState(Utils.Logger logger)
        {
            return _config;
        }

        /// <summary>
        /// Set the node state
        /// </summary>
        /// <param name="state"></param>
        /// <param name="logger"></param>
        public void SetState(object state, Utils.Logger logger)
        {
            T config = state as T;

            if (state == null)
            {
                logger.LogError(Properties.Resources.PersistNodeImpl_InvalidConfig, GetType().Name);
            }
            else
            {
                ValidateConfig(config);
                _config = config;
            }
        }

        #endregion
    }
}
