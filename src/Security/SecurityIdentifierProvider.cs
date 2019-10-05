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

namespace ManagedSandbox.Security
{
    public class SecurityIdentifierProvider : ISecurityIdentifierProvider
    {
        private readonly Lazy<WindowsIdentity> currentUserIdentity;
        private readonly Lazy<SecurityIdentifier> currentUserSid;
        private readonly Lazy<SecurityIdentifier> everyoneSid;
        private readonly Lazy<SecurityIdentifier> interactiveSid;
        private readonly Lazy<SecurityIdentifier> localSystemSid;
        private readonly Lazy<SecurityIdentifier> logonSid;
        private readonly Lazy<SecurityIdentifier> networkServiceSid;
        private readonly Lazy<SecurityIdentifier> usersSid;
        private readonly Lazy<SecurityIdentifier> restrictedSid;

        public SecurityIdentifierProvider()
        {
            this.currentUserIdentity = new Lazy<WindowsIdentity>(() => WindowsIdentity.GetCurrent());
            this.currentUserSid = new Lazy<SecurityIdentifier>(() => this.currentUserIdentity.Value.User);
            this.everyoneSid = new Lazy<SecurityIdentifier>(() => new SecurityIdentifier("S-1-1-0"));
            this.interactiveSid = new Lazy<SecurityIdentifier>(() => new SecurityIdentifier("S-1-5-4"));
            this.localSystemSid = new Lazy<SecurityIdentifier>(() => new SecurityIdentifier("S-1-5-18"));
            this.logonSid = new Lazy<SecurityIdentifier>(this.GetLogonSid);
            this.networkServiceSid = new Lazy<SecurityIdentifier>(() => new SecurityIdentifier("S-1-5-20"));
            this.usersSid = new Lazy<SecurityIdentifier>(() => new SecurityIdentifier("S-1-5-32-545"));
            this.restrictedSid = new Lazy<SecurityIdentifier>(() => new SecurityIdentifier("S-1-5-12"));
        }

        public SecurityIdentifier CurrentUser => this.currentUserSid.Value;

        public SecurityIdentifier Everyone => this.everyoneSid.Value;

        public SecurityIdentifier Interactive => this.interactiveSid.Value;

        public SecurityIdentifier LocalSystem => this.localSystemSid.Value;

        public SecurityIdentifier Logon => this.logonSid.Value;

        public SecurityIdentifier NetworkService => this.networkServiceSid.Value;

        public SecurityIdentifier Users => this.usersSid.Value;

        public SecurityIdentifier Restricted => this.restrictedSid.Value;

        private SecurityIdentifier GetLogonSid()
        {
            // Get the token for the current user. Note that we need to create a SafeTokenHandle of the token in order to safely call
            // the token functions, but the token that's available is owned by the WindowsIdentity instance and should not be closed
            // after we're done with it.
            using (var currentToken = new SafeTokenHandle(this.currentUserIdentity.Value.Token, ownsHandle: false))
            {
                // Get the current access token and query it for the token groups. The logon SID can then be extracted by
                // enumerating the resulting structures.
                int tokenInformationLength;

                Methods.GetTokenInformation(
                    currentToken,
                    TOKEN_INFORMATION_CLASS.TokenGroups,
                    IntPtr.Zero,
                    0 /* tokenInformationLength */,
                    out tokenInformationLength);
                if (tokenInformationLength <= 0)
                {
                    throw
                        new SandboxException(
                            "Unable to determine length of the current token information",
                            new Win32Exception());
                }

                using (var nativeTokenInformation = new SafeHGlobalBuffer(tokenInformationLength))
                {
                    Methods.GetTokenInformation(
                        currentToken,
                        TOKEN_INFORMATION_CLASS.TokenGroups,
                        nativeTokenInformation.DangerousGetHandle(),
                        nativeTokenInformation.Size,
                        out tokenInformationLength);
                    if (tokenInformationLength <= 0)
                    {
                        throw
                            new SandboxException(
                                "Unabled to get the current token information",
                                new Win32Exception());
                    }

                    var tokenGroups = (TOKEN_GROUPS)Marshal.PtrToStructure(
                        nativeTokenInformation.DangerousGetHandle(),
                        typeof(TOKEN_GROUPS));
                    int sidAndAttributeSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));

                    // Get a pointer to the start of the Groups array.
                    IntPtr groupsPtr = IntPtr.Add(
                        nativeTokenInformation.DangerousGetHandle(),
                        (int)Marshal.OffsetOf(typeof(TOKEN_GROUPS), "Groups"));

                    // Now iterate through all of the groups and look for our Logon SID.
                    for (int i = 0; i < tokenGroups.GroupCount; i++)
                    {
                        var sidAndAttributes = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                            IntPtr.Add(groupsPtr, i * sidAndAttributeSize),
                            typeof(SID_AND_ATTRIBUTES));
                        if ((sidAndAttributes.Attributes & SID_ATTRIBUTES.SE_GROUP_LOGON_ID) == SID_ATTRIBUTES.SE_GROUP_LOGON_ID)
                        {
                            return new SecurityIdentifier(sidAndAttributes.Sid);
                        }
                    }
                }
            }

            // LocalSystem doesn't have a Logon SID and and so it's not possible to create a restricted process using
            // this approach for processes executing using that identity. Since this is a known scenario make sure the
            // error message helps debug it.
            if (this.CurrentUser == this.LocalSystem)
            {
                throw new SandboxException(
                    "Cannot create a restricted process as LocalSystem (does not have a Logon SID)");
            }

            throw new SandboxException(
                "Could not determine the Logon SID required to generate a restricted token");
        }
    }
}
