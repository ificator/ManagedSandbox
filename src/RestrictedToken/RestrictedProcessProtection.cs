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
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using ManagedSandbox.Native;
using ManagedSandbox.Security;
using ManagedSandbox.Tracing;

namespace ManagedSandbox.RestrictedToken
{
    public class RestrictedProcessProtection : IPrincipalProvider, IProtection
    {
        private const string DefaultDaclTemplate = @"D:(A;;0x1f0fff;;;BA)(A;;0x1fffff;;;SY)(A;;0x1fffff;;;{0})";

        private readonly DisposalEscrow disposalEscrow = new DisposalEscrow();
        private readonly IIdentityProvider identityProvider;
        private readonly ITracer tracer;

        private SafeTokenHandle restrictedTokenHandle;

        public RestrictedProcessProtection(
            IIdentityProvider securityIdentifierProvider,
            ITracer tracer)
        {
            this.identityProvider = securityIdentifierProvider;
            this.tracer = tracer;
        }

        public void Dispose()
        {
            this.disposalEscrow.Dispose();
        }

        public string GetMandatoryLevelSacl()
        {
            // Sacl:(Mandatory Label;;No Write Up;;Low)
            return "S:(ML;;NW;;;LW)";
        }

        public IEnumerable<SecurityIdentifier> GetSecurityIdentifiers()
        {
            yield return this.identityProvider.LogonSid;
        }

        public void ModifyProcess(Process process)
        {
        }

        public void ModifyStartup(ref STARTUPINFOEX startupInfoEx, ref CREATE_PROCESS_FLAGS createProcessFlags)
        {
        }

        public void ModifyToken(ref SafeTokenHandle currentToken)
        {
            currentToken = this.GetRestrictedToken();
        }

        private SafeTokenHandle GetRestrictedToken()
        {
            if (this.restrictedTokenHandle == null)
            {
                using (var localDisposalEscrow = new DisposalEscrow())
                {
                    // The first step in creating a restricted token is to enumerate the existing one and decide which of
                    // the SIDs we want to deny, and which of the SIDs we want to restrict. For our purposes we want:
                    // 
                    // DENY all except:
                    //      CurrentUser
                    //      Everyone
                    //      Users
                    //      Interactive
                    //      Logon
                    // 
                    // RESTRICT only:
                    //      CurrentUser
                    //      Everyone
                    //      Users
                    //      Logon
                    //      Restricted

                    var sidsToDeny = new List<SID_AND_ATTRIBUTES>();
                    var sidsToRestrict = new List<SID_AND_ATTRIBUTES>();

                    foreach (IdentityReference identityReference in this.identityProvider.CurrentUser.Groups)
                    {
                        var securityIdentifier = (SecurityIdentifier)identityReference.Translate(typeof(SecurityIdentifier));

                        if (securityIdentifier.Equals(this.identityProvider.EveryoneSid) ||
                            securityIdentifier.Equals(this.identityProvider.UsersSid))
                        {
                            // Add the group to the restricted list if it's one of the special groups we want to allow.
                            sidsToRestrict.Add(
                                RestrictedProcessProtection.ConvertSecurityIdentifierToSidAndAttributes(securityIdentifier, localDisposalEscrow));
                        }
                        else if (!securityIdentifier.Equals(this.identityProvider.InteractiveSid))
                        {
                            // Otherwise add the group to the deny list, but special case the Interactive SID which
                            // shouldn't be denied and also not restricted.
                            sidsToDeny.Add(
                                RestrictedProcessProtection.ConvertSecurityIdentifierToSidAndAttributes(securityIdentifier, localDisposalEscrow));
                        }
                    }

                    // There are a set of non-group SIDs that we want to always restrict and never deny, so add them to
                    // the appropriate lists.
                    sidsToRestrict.Add(
                        RestrictedProcessProtection.ConvertSecurityIdentifierToSidAndAttributes(
                            this.identityProvider.CurrentUserSid,
                            localDisposalEscrow));
                    sidsToRestrict.Add(
                        RestrictedProcessProtection.ConvertSecurityIdentifierToSidAndAttributes(
                            this.identityProvider.LogonSid,
                            localDisposalEscrow));
                    sidsToRestrict.Add(
                        RestrictedProcessProtection.ConvertSecurityIdentifierToSidAndAttributes(
                            this.identityProvider.RestrictedSid,
                            localDisposalEscrow));

                    this.tracer.Trace(nameof(RestrictedProcessProtection), "Creating restricted token");

                    // Now that we have all the SIDs in the correct buckets we can call the native method to generate our
                    // new token.
                    SafeTokenHandle newTokenHandle;
                    if (!Methods.CreateRestrictedToken(
                            localDisposalEscrow.Add(new SafeTokenHandle(this.identityProvider.CurrentUser.Token, ownsHandle: false)),
                            RESTRICTED_TOKEN_FLAGS.DISABLE_MAX_PRIVILEGE,
                            (uint)sidsToDeny.Count,
                            sidsToDeny.ToArray(),
                            0 /* deletePrivilegeCount */,
                            null /* privilegesToDelete */,
                            (uint)sidsToRestrict.Count,
                            sidsToRestrict.ToArray(),
                            out newTokenHandle))
                    {
                        throw
                            new SandboxException(
                                "Unable to create restricted token",
                                new Win32Exception());
                    }

                    // We'll add the token here in case something breaks, but we'll remove it before we return the token at
                    // the end of this method.
                    localDisposalEscrow.Add(newTokenHandle);

                    this.tracer.Trace(nameof(RestrictedProcessProtection), "Adding mandatory low SID");

                    // Create the low integrity SID.
                    SafeSecurityIdentifier restrictedSecurityIdentifierNative;
                    if (!Methods.AllocateAndInitializeSid(
                        ref Constants.SECURITY_MANDATORY_LABEL_AUTHORITY,
                        1 /* nSubAuthorityCount */,
                        (int)SECURITY_MANDATOR_RID.LOW,
                        0 /* dwSubAuthority1 */,
                        0 /* dwSubAuthority2 */,
                        0 /* dwSubAuthority3 */,
                        0 /* dwSubAuthority4 */,
                        0 /* dwSubAuthority5 */,
                        0 /* dwSubAuthority6 */,
                        0 /* dwSubAuthority7 */,
                        out restrictedSecurityIdentifierNative))
                    {
                        throw
                            new SandboxException(
                                "Unable to allocate and initialize low integrity SID",
                                new Win32Exception());
                    }

                    // Set the integrity level in the access token to low using the low integrity SID we just created.
                    TOKEN_MANDATORY_LABEL managedTokenMandatoryLabel;
                    managedTokenMandatoryLabel.Label.Attributes = SID_ATTRIBUTES.SE_GROUP_INTEGRITY;
                    managedTokenMandatoryLabel.Label.Sid = restrictedSecurityIdentifierNative.DangerousGetHandle();

                    var nativeTokenMandatoryLabel = localDisposalEscrow.Add(new SafeHGlobalBuffer(Marshal.SizeOf(managedTokenMandatoryLabel)));
                    Marshal.StructureToPtr(managedTokenMandatoryLabel, nativeTokenMandatoryLabel.DangerousGetHandle(), false);

                    if (!Methods.SetTokenInformation(
                        newTokenHandle,
                        TOKEN_INFORMATION_CLASS.TokenIntegrityLevel,
                        nativeTokenMandatoryLabel.DangerousGetHandle(),
                        nativeTokenMandatoryLabel.Size +
                        Methods.GetLengthSid(restrictedSecurityIdentifierNative.DangerousGetHandle())))
                    {
                        throw
                            new SandboxException(
                                "Unable to set token integrity level",
                                new Win32Exception());
                    }

                    this.tracer.Trace(nameof(RestrictedProcessProtection), "Granting login SID access to token");

                    // Now modify the access token to set the DACL so that the Logon SID has appropriate access to any
                    // processes started using the token. Without this things mostly work, but the process will be
                    // restricted in ways that .NET doesn't like (E.g. it's not possible to get the token associated with
                    // the process)
                    var defaultDaclDescriptor = new RawSecurityDescriptor(
                        string.Format(
                            RestrictedProcessProtection.DefaultDaclTemplate,
                            this.identityProvider.LogonSid.Value));

                    var managedDefaultDacl = new byte[defaultDaclDescriptor.DiscretionaryAcl.BinaryLength];
                    defaultDaclDescriptor.DiscretionaryAcl.GetBinaryForm(managedDefaultDacl, 0 /* offset */);

                    var nativeDefaultDacl = localDisposalEscrow.Add(new SafeHGlobalBuffer(managedDefaultDacl.Length));
                    Marshal.Copy(
                        managedDefaultDacl,
                        0 /* startIndex */,
                        nativeDefaultDacl.DangerousGetHandle(),
                        managedDefaultDacl.Length);

                    TOKEN_DEFAULT_DACL managedTokenDefaultDacl;
                    managedTokenDefaultDacl.DefaultDacl = nativeDefaultDacl.DangerousGetHandle();

                    var nativeTokenDefaultDacl = localDisposalEscrow.Add(new SafeHGlobalBuffer(Marshal.SizeOf(managedTokenDefaultDacl)));
                    Marshal.StructureToPtr(managedTokenDefaultDacl, nativeTokenDefaultDacl.DangerousGetHandle(), false /* fDeleteOld */);

                    if (!Methods.SetTokenInformation(
                        newTokenHandle,
                        TOKEN_INFORMATION_CLASS.TokenDefaultDacl,
                        nativeTokenDefaultDacl.DangerousGetHandle(),
                        nativeTokenDefaultDacl.Size))
                    {
                        throw
                            new SandboxException(
                                "Unable to set the DACL to give the Logon SID access to the process",
                                new Win32Exception());
                    }

                    this.disposalEscrow.Transfer(localDisposalEscrow, newTokenHandle);
                    this.restrictedTokenHandle = newTokenHandle;
                }
            }

            return this.restrictedTokenHandle;
        }

        private static SID_AND_ATTRIBUTES ConvertSecurityIdentifierToSidAndAttributes(
            SecurityIdentifier securityIdentifier,
            DisposalEscrow disposalEscrow)
        {
            var sidBytes = new byte[securityIdentifier.BinaryLength];
            securityIdentifier.GetBinaryForm(sidBytes, 0 /* offset */);

            var nativeBytes = disposalEscrow.Add(new SafeHGlobalBuffer(sidBytes.Length));

            Marshal.Copy(sidBytes, 0 /* startIndex */, nativeBytes.DangerousGetHandle(), sidBytes.Length);

            return new SID_AND_ATTRIBUTES
            {
                Sid = nativeBytes.DangerousGetHandle(),
            };
        }
    }
}
