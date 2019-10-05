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
        private readonly SafeProcThreadAttributeList attributeListHandle;
        private readonly DisposalEscrow disposalEscrow;
        private readonly SafeSecurityIdentifier securityIdentifierHandle;
        private readonly ITracer tracer;

        private AppContainer(ITracer tracer, string name, SafeSecurityIdentifier securityIdentifierHandle)
        {
            if (tracer == null)
            {
                throw new ArgumentNullException(nameof(tracer));
            }

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

            this.disposalEscrow = new DisposalEscrow();
            this.securityIdentifierHandle = securityIdentifierHandle;
            this.tracer = tracer;

            this.attributeListHandle = this.AllocateAttributeList();
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
        /// <param name="tracer">A tracer instance.</param>
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
                AppContainer newAppContainer = AppContainer.CreateProfile(tracer, appContainerName, displayName, description);
                tracer.Trace(nameof(AppContainer), "AppContainerCid = {0}", newAppContainer.SecurityIdentifier);
                return newAppContainer;
            }
            catch (SandboxException ex)
            {
                if (ex.HResult == HResult.AlreadyExists)
                {
                    tracer.Trace(nameof(AppContainer), "Profile already existed for '{0}'", appContainerName);
                    AppContainer existingAppContainer = AppContainer.DeriveFromName(tracer, appContainerName);
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
            this.disposalEscrow.Dispose();
            this.securityIdentifierHandle.Dispose();
        }

        /// <summary>
        /// Sets the attributes so that the process launched using the <see cref="STARTUPINFOEX"/> will be in the AppContainer.
        /// </summary>
        /// <param name="startupInfoEx">The structure to modify.</param>
        public void SetAttributeList(ref STARTUPINFOEX startupInfoEx)
        {
            this.tracer.Trace(nameof(AppContainer), "Setting attribute list");
            startupInfoEx.lpAttributeList = this.attributeListHandle.DangerousGetHandle();
        }

        private static AppContainer CreateProfile(
            ITracer tracer,
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
                return new AppContainer(tracer, appContainerName, appContainerSid);
            }
            catch
            {
                appContainerSid.Dispose();
                throw;
            }
        }

        private static AppContainer DeriveFromName(ITracer tracer, string appContainerName)
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
                return new AppContainer(tracer, appContainerName, appContainerSid);
            }
            catch
            {
                appContainerSid.Dispose();
                throw;
            }
        }

        private SafeProcThreadAttributeList AllocateAttributeList()
        {
            using (var localDisposalEscrow = new DisposalEscrow())
            {
                SECURITY_CAPABILITIES securityCapabilities = new SECURITY_CAPABILITIES();
                this.SetSecurityCapabilities(
                    ref securityCapabilities,
                    this.securityIdentifierHandle,
                    new WELL_KNOWN_SID_TYPE[] { WELL_KNOWN_SID_TYPE.WinCapabilityInternetClientSid });

                var attributeListHandle = localDisposalEscrow.Add(new SafeProcThreadAttributeList(1));
                var securityCapabilitiesMemory = localDisposalEscrow.Add(new SafeHGlobalBuffer(Marshal.SizeOf(securityCapabilities)));

                Marshal.StructureToPtr(securityCapabilities, securityCapabilitiesMemory.DangerousGetHandle(), fDeleteOld: false);

                if (!Methods.UpdateProcThreadAttribute(
                        attributeListHandle.DangerousGetHandle(),
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

                this.disposalEscrow.Subsume(localDisposalEscrow);
                return attributeListHandle;
            }
        }

        private void SetSecurityCapabilities(
            ref SECURITY_CAPABILITIES securityCapabilities,
            SafeSecurityIdentifier appContainerSid,
            WELL_KNOWN_SID_TYPE[] appCapabilities)
        {
            using (var localDisposalEscrow = new DisposalEscrow())
            {
                securityCapabilities.AppContainerSid = appContainerSid.DangerousGetHandle();
                securityCapabilities.Capabilities = IntPtr.Zero;
                securityCapabilities.CapabilityCount = 0;
                securityCapabilities.Reserved = 0;

                if (appCapabilities != null && appCapabilities.Length > 0)
                {
                    var attributesMemory = localDisposalEscrow.Add(new SafeHGlobalBuffer(Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)) * appCapabilities.Length));

                    for (int i = 0; i < appCapabilities.Length; i++)
                    {
                        Int32 sidSize = Constants.SECURITY_MAX_SID_SIZE;

                        var safeMemory = localDisposalEscrow.Add(new SafeHGlobalBuffer(sidSize));

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

                    securityCapabilities.Capabilities = attributesMemory.DangerousGetHandle();
                    securityCapabilities.CapabilityCount = appCapabilities.Length;
                }

                this.disposalEscrow.Subsume(localDisposalEscrow);
            }
        }
    }
}
