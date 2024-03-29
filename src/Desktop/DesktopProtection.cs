﻿/*
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

using System.Collections.Generic;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using ManagedSandbox.Native;
using ManagedSandbox.Security;
using ManagedSandbox.Tracing;

namespace ManagedSandbox.Desktop
{
    public class DesktopProtection : IProtection
    {
        public DesktopProtection(
            IEnumerable<IPrincipalProvider> principalProviders,
            ITracer tracer)
        {
            string mandatoryLevelSacl = null;
            foreach (var principalProvider in principalProviders)
            {
                string tempMandatoryLevelSacl = principalProvider.GetMandatoryLevelSacl();
                if (tempMandatoryLevelSacl != null)
                {
                    if (mandatoryLevelSacl != null)
                    {
                        throw new SandboxException("Multiple SDDLs available - only one can be used.");
                    }

                    mandatoryLevelSacl = tempMandatoryLevelSacl;
                }
            }

            this.Desktop = Desktop.Create(tracer, mandatoryLevelSacl);

            var desktopSecurity = new DesktopSecurity(
                this.Desktop,
                AccessControlSections.Access);
            foreach (var principalProvider in principalProviders)
            {
                IEnumerable<SecurityIdentifier> securityIdentifiers = principalProvider.GetSecurityIdentifiers();
                if (securityIdentifiers != null)
                {
                    foreach (SecurityIdentifier securityIdentifier in securityIdentifiers)
                    {
                        tracer.Trace(nameof(DesktopProtection), $"Granting access to desktop {this.Desktop.Name} to {securityIdentifier}");
                        desktopSecurity.SetAccessRule(
                            new DesktopAccessRule(
                                securityIdentifier,
                                DesktopRights.GENERIC_READ |
                                DesktopRights.DESKTOP_WRITEOBJECTS,
                                AccessControlType.Allow));
                    }
                }
            }
            desktopSecurity.Commit();
        }

        /// <summary>
        /// The <see cref="Desktop"/> instance utilized for this protection.
        /// </summary>
        public Desktop Desktop { get; }

        public void Dispose()
        {
            this.Desktop.Dispose();
        }

        public void ModifyProcess(Process process)
        {
        }

        public void ModifyStartup(ref STARTUPINFOEX startupInfoEx, ref CREATE_PROCESS_FLAGS createProcessFlags)
        {
            using (var windowStation = WindowStation.GetCurrent())
            {
                startupInfoEx.StartupInfo.lpDesktop = windowStation.Name + "\\" + this.Desktop.Name;
            }
        }

        public void ModifyToken(ref SafeTokenHandle currentToken)
        {
        }
    }
}
