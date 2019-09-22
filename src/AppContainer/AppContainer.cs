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

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using ManagedSandbox.Native;
using ManagedSandbox.Tracing;

namespace ManagedSandbox.AppContainer
{
    public class AppContainer : IDisposable
    {
        private readonly SafeHGlobalBuffer attributeListHandle;
        private readonly SafeSecurityIdentifier securityIdentifierHandle;

        private AppContainer(string name, SafeSecurityIdentifier securityIdentifierHandle)
        {
            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (securityIdentifierHandle == null)
            {
                throw new ArgumentNullException(nameof(securityIdentifierHandle));
            }

            this.Name = name;
            this.SecurityIdentifier = new SecurityIdentifier(securityIdentifierHandle.DangerousGetHandle());

            if (Methods.GetAppContainerFolderPath(this.SecurityIdentifier.Value, out string folderPath) == HResult.OK)
            {
                this.FolderPath = folderPath;
            }

            this.attributeListHandle = AppContainer.AllocateAttributeList(securityIdentifierHandle);
            this.securityIdentifierHandle = securityIdentifierHandle;
        }

        /// <summary>
        /// The path of the local app data folder for the AppContainer.
        /// </summary>
        public string FolderPath { get; }

        /// <summary>
        /// The name of the AppContainer.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// The SID of the AppContainer.
        /// </summary>
        public SecurityIdentifier SecurityIdentifier { get; }

        /// <summary>
        /// Attempts to create the AppContainerProfile, and get the associated AppContainer SID. If the profile already exists the
        /// provided name will be used to derive the AppContainer SID.
        /// </summary>
        /// <param name="appContainerName">The name of the AppContainer.</param>
        /// <param name="displayName">The display name of the AppContainer.</param>
        /// <param name="description">The description of the AppContainer.</param>
        /// <returns>The <see cref="AppContainer"/> instance.</returns>
        public static AppContainer Create(
            ITracer tracer,
            string appContainerName,
            string displayName = null,
            string description = null)
        {
            appContainerName = appContainerName ?? throw new ArgumentNullException(nameof(appContainerName));
            displayName = displayName ?? appContainerName;
            description = description ?? displayName;

            try
            {
                tracer.Trace(nameof(AppContainer), "Creating profile for '{0}'", appContainerName);
                AppContainer newAppContainer = AppContainer.CreateProfile(appContainerName, displayName, description);
                tracer.Trace(nameof(AppContainer), "AppContainerCid = {0}", newAppContainer.SecurityIdentifier);
                return newAppContainer;
            }
            catch (SandboxException ex)
            {
                if (ex.HResult == HResult.AlreadyExists)
                {
                    tracer.Trace(nameof(AppContainer), "Profile already existed for '{0}'", appContainerName);
                    AppContainer existingAppContainer = AppContainer.DeriveFromName(appContainerName);
                    tracer.Trace(nameof(AppContainer), "AppContainerCid = {0}", existingAppContainer.SecurityIdentifier);
                    return existingAppContainer;
                }

                throw;
            }
        }

        /// <summary>
        /// Deletes the AppContainer.
        /// </summary>
        public void Delete()
        {
            Methods.DeleteAppContainerProfile(this.Name);
        }

        public void Dispose()
        {
            this.attributeListHandle.Dispose();
            this.securityIdentifierHandle.Dispose();
        }

        /// <summary>
        /// Sets the attributes so that the process launched using the <see cref="STARTUPINFOEX"/> will be in the AppContainer.
        /// </summary>
        /// <param name="startupInfoEx">The structure to modify.</param>
        public void SetAttributeList(ref STARTUPINFOEX startupInfoEx)
        {
            startupInfoEx.lpAttributeList = this.attributeListHandle.DangerousGetHandle();
        }

        private static SafeHGlobalBuffer AllocateAttributeList(SafeSecurityIdentifier securityIdentifierHandle)
        {
            SECURITY_CAPABILITIES securityCapabilities = new SECURITY_CAPABILITIES();
            AppContainer.SetSecurityCapabilities(
                ref securityCapabilities,
                securityIdentifierHandle,
                new WELL_KNOWN_SID_TYPE[] { WELL_KNOWN_SID_TYPE.WinCapabilityInternetClientSid });

            Int32 size = 0;
            Methods.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);

            var attributeListMemory = new SafeHGlobalBuffer(size);
            try
            {
                if (!Methods.InitializeProcThreadAttributeList(attributeListMemory.DangerousGetHandle(), 1, 0, ref size))
                {
                    throw new SandboxException(
                        "Unable to initialize process thread attribute list.",
                        new Win32Exception());
                }

                var securityCapabilitiesMemory = new SafeHGlobalBuffer(Marshal.SizeOf(securityCapabilities));
                Marshal.StructureToPtr(securityCapabilities, securityCapabilitiesMemory.DangerousGetHandle(), fDeleteOld: false);

                if (!Methods.UpdateProcThreadAttribute(
                        attributeListMemory.DangerousGetHandle(),
                        dwFlags: 0,
                        attribute: PROC_THREAD_ATTRIBUTES.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                        securityCapabilitiesMemory.DangerousGetHandle(),
                        securityCapabilitiesMemory.Size,
                        lpPreviousValue: IntPtr.Zero,
                        lpReturnSize: IntPtr.Zero))
                {
                    throw new SandboxException(
                        $"Failed to update proc thread attribute list (0x{Marshal.GetLastWin32Error():X08})",
                        new Win32Exception()); ;
                }

                return attributeListMemory;
            }
            catch
            {
                attributeListMemory.Dispose();
                throw;
            }
        }

        private static AppContainer CreateProfile(
            string appContainerName,
            string displayName = null,
            string description = null)
        {
            SafeSecurityIdentifier appContainerSid;
            HResult result = Methods.CreateAppContainerProfile(
                appContainerName,
                displayName,
                description,
                pCapabilities: null,
                dwCapabilityCount: 0,
                out appContainerSid);
            if (result != HResult.OK)
            {
                throw new SandboxException(
                    "Unable to create AppContainerProfile",
                    result);
            }

            try
            {
                return new AppContainer(appContainerName, appContainerSid);
            }
            catch
            {
                appContainerSid.Dispose();
                throw;
            }
        }

        private static AppContainer DeriveFromName(string appContainerName)
        {
            SafeSecurityIdentifier appContainerSid = null;
            HResult result = Methods.DeriveAppContainerSidFromAppContainerName(appContainerName, out appContainerSid);
            if (result != HResult.OK)
            {
                throw new SandboxException(
                    "Unable to get AppContainerProfile",
                    result);
            }

            try
            {
                return new AppContainer(appContainerName, appContainerSid);
            }
            catch
            {
                appContainerSid.Dispose();
                throw;
            }
        }

        private static void SetSecurityCapabilities(
            ref SECURITY_CAPABILITIES securityCapabilities,
            SafeSecurityIdentifier appContainerSid,
            WELL_KNOWN_SID_TYPE[] appCapabilities)
        {
            securityCapabilities.AppContainerSid = appContainerSid.DangerousGetHandle();
            securityCapabilities.Capabilities = IntPtr.Zero;
            securityCapabilities.CapabilityCount = 0;
            securityCapabilities.Reserved = 0;

            if (appCapabilities != null && appCapabilities.Length > 0)
            {
                // BUGBUG: We can use "SecurityIdentifier" instead of the custom wellknownsidtype and lookup.

                var disposables = new System.Collections.Generic.List<IDisposable>();
                var attributesMemory = new SafeHGlobalBuffer(Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)) * appCapabilities.Length);

                try
                {
                    // BUGBUG: Probably doesn't clean up, but what is the lifetime?
                    disposables.Add(attributesMemory);

                    for (int i = 0; i < appCapabilities.Length; i++)
                    {
                        Int32 sidSize = Constants.SECURITY_MAX_SID_SIZE;

                        // BUGBUG: Leaks on success
                        var safeMemory = new SafeHGlobalBuffer(sidSize);
                        disposables.Add(safeMemory);

                        if (!Methods.CreateWellKnownSid(appCapabilities[i], IntPtr.Zero, safeMemory, ref sidSize))
                        {
                            throw new SandboxException(
                                "Unable to create well known sid.",
                                new Win32Exception());
                        }

                        var attribute = new SID_AND_ATTRIBUTES
                        {
                            Attributes = SID_ATTRIBUTES.SE_GROUP_ENABLED,
                            Sid = safeMemory.DangerousGetHandle(),
                        };

                        Marshal.StructureToPtr(attribute, IntPtr.Add(attributesMemory.DangerousGetHandle(), i * Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES))), fDeleteOld: false);
                    }
                }
                catch
                {
                    foreach (IDisposable disposable in disposables)
                    {
                        disposable.Dispose();
                    }

                    throw;
                }

                securityCapabilities.Capabilities = attributesMemory.DangerousGetHandle();
                securityCapabilities.CapabilityCount = appCapabilities.Length;
            }
        }

    }
}
