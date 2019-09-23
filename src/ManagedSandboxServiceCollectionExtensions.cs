/*
 * MIT License
 * 
 * Copyright (c) 2019 ificator
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using ManagedSandbox.AppContainer;
using ManagedSandbox.Desktop;
using ManagedSandbox.JobObject;
using ManagedSandbox.Tracing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ManagedSandbox
{
    public static class ManagedSandboxServiceCollectionExtensions
    {
        public static IServiceCollection AddAppContainerProtection(
            this IServiceCollection services,
            string appContainerName,
            string displayName = null,
            string description = null)
        {
            services.AddTransient<IProtection, AppContainerProtection>(
                x => new AppContainerProtection(x.GetService<ITracer>(), appContainerName, displayName, description));

            return services;
        }

        public static IServiceCollection AddConsoleTracer(this IServiceCollection services)
        {
            services.Replace(new ServiceDescriptor(typeof(ITracer), typeof(ConsoleTracer), ServiceLifetime.Transient));

            return services;
        }

        public static IServiceCollection AddDesktopProtection(this IServiceCollection services)
        {
            services.AddTransient<IProtection, DesktopProtection>();

            return services;
        }

        public static IServiceCollection AddFileTracer(this IServiceCollection services, string fileName)
        {
            services.Replace(new ServiceDescriptor(typeof(ITracer), x => new FileTracer(fileName), ServiceLifetime.Transient));

            return services;
        }

        public static IServiceCollection AddJobObjectProtection(this IServiceCollection services)
        {
            services.AddTransient<IProtection, JobObjectProtection>();

            return services;
        }

        public static IServiceCollection AddManagedSandbox(this IServiceCollection services)
        {
            services.AddTransient<SandboxedProcess>();
            services.AddTransient<ITracer, NullTracer>();

            return services;
        }
    }
}
