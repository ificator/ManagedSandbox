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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;
using ManagedSandbox.Native;
using ManagedSandbox.Security;
using ManagedSandbox.Tracing;

namespace ManagedSandbox.AppContainer
{
    public class AppContainerProtection : IDisposable, IPrincipalProvider, IProtection
    {
        public AppContainerProtection(
            ITracer tracer,
            string appContainerName,
            string displayName = null,
            string description = null)
        {
            this.AppContainer = AppContainer.Create(tracer, appContainerName, displayName, description);
        }

        /// <summary>
        /// The <see cref="AppContainer"/> instance utilized for this protection.
        /// </summary>
        public AppContainer AppContainer { get; }

        public void Dispose()
        {
            this.AppContainer.Dispose();
        }

        public string GetMandatoryLevelSacl()
        {
            return null;
        }

        public IEnumerable<SecurityIdentifier> GetSecurityIdentifiers()
        {
            yield return this.AppContainer.SecurityIdentifier;
        }

        public void ModifyProcess(Process process)
        {
        }

        public void ModifyStartup(ref STARTUPINFOEX startupInfoEx, ref CREATE_PROCESS_FLAGS createProcessFlags)
        {
            this.AppContainer.SetAttributeList(ref startupInfoEx);
        }

        public void ModifyToken(ref SafeTokenHandle currentToken)
        {
        }
    }
}
