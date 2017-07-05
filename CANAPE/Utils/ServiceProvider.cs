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
using System.Collections.Generic;

namespace CANAPE.Utils
{
    /// <summary>
    /// CANAPE IServiceProvider, used to access parts of the system in a decoupled way
    /// </summary>
    public sealed class ServiceProvider
    {
        private static ServiceProvider _provider;

        static ServiceProvider()
        {
            _provider = new ServiceProvider();
        }

        private Dictionary<Type, object> _services;

        /// <summary>
        /// Constructor
        /// </summary>
        public ServiceProvider()
        {
            _services = new Dictionary<Type, object>();
        }

        /// <summary>
        /// Get the current static provider instance
        /// </summary>
        public static ServiceProvider GlobalInstance { get { return _provider; } }

        /// <summary>
        /// Get a service
        /// </summary>
        /// <typeparam name="T">The type of service to get</typeparam>
        /// <returns>The service or null if it doesn't exist</returns>
        public T GetService<T>() where T : class
        {
            return GetService(typeof(T)) as T;
        }

        /// <summary>
        /// Get a service for a particular type
        /// </summary>
        /// <param name="serviceType">The type of service</param>
        /// <returns>The service object if found, otherwise false</returns>
        public object GetService(Type serviceType)
        {
            lock (_services)
            {
                if (_services.ContainsKey(serviceType))
                {
                    return _services[serviceType];
                }
                else
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// Register a new service
        /// </summary>
        /// <param name="serviceType">The service type</param>
        /// <param name="serviceObject">The object which implements this service</param>
        public void RegisterService(Type serviceType, object serviceObject)
        {
            lock (_services)
            {
                _services[serviceType] = serviceObject;
            }
        }

        /// <summary>
        /// Unregister a service
        /// </summary>
        /// <param name="serviceType">The service type</param>
        public void UnregisterService(Type serviceType)
        {
            lock (_services)
            {
                _services.Remove(serviceType);
            }
        }
    }
}
