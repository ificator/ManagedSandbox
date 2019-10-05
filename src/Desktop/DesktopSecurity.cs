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
using System.Security.AccessControl;
using System.Security.Principal;

namespace ManagedSandbox.Desktop
{
    [Flags]
    public enum DesktopRights : uint
    {
        NONE = 0x00000000,

        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,

        DESKTOP_ALL_ACCESS = DESKTOP_READOBJECTS |
                                      DESKTOP_CREATEWINDOW |
                                      DESKTOP_CREATEMENU |
                                      DESKTOP_HOOKCONTROL |
                                      DESKTOP_JOURNALRECORD |
                                      DESKTOP_JOURNALPLAYBACK |
                                      DESKTOP_ENUMERATE |
                                      DESKTOP_WRITEOBJECTS |
                                      DESKTOP_SWITCHDESKTOP,

        STANDARD_DELETE = 0x00010000,
        STANDARD_READPERMISSIONS = 0x00020000,
        STANDARD_WRITEPERMISSIONS = 0x00040000,
        STANDARD_TAKEOWNERSHIP = 0x00080000,
        STANDARD_SYNCHRONIZE = 0x00100000,

        STANDARD_RIGHTS_ALL = STANDARD_DELETE |
                                      STANDARD_READPERMISSIONS |
                                      STANDARD_SYNCHRONIZE |
                                      STANDARD_TAKEOWNERSHIP |
                                      STANDARD_WRITEPERMISSIONS,
        STANDARD_RIGHTS_EXECUTE = STANDARD_READPERMISSIONS,
        STANDARD_RIGHTS_READ = STANDARD_READPERMISSIONS,
        STANDARD_RIGHTS_REQUIRED = STANDARD_DELETE |
                                      STANDARD_READPERMISSIONS |
                                      STANDARD_TAKEOWNERSHIP |
                                      STANDARD_WRITEPERMISSIONS,
        STANDARD_RIGHTS_WRITE = STANDARD_READPERMISSIONS,

        GENERIC_READ = DESKTOP_ENUMERATE |
                                      DESKTOP_READOBJECTS |
                                      STANDARD_RIGHTS_READ,
        GENERIC_WRITE = DESKTOP_CREATEMENU |
                                      DESKTOP_CREATEWINDOW |
                                      DESKTOP_HOOKCONTROL |
                                      DESKTOP_JOURNALPLAYBACK |
                                      DESKTOP_JOURNALRECORD |
                                      DESKTOP_WRITEOBJECTS |
                                      STANDARD_RIGHTS_WRITE,
        GENERIC_EXECUTE = DESKTOP_SWITCHDESKTOP |
                                      STANDARD_RIGHTS_EXECUTE,
        GENERIC_ALL = DESKTOP_CREATEMENU |
                                      DESKTOP_CREATEWINDOW |
                                      DESKTOP_ENUMERATE |
                                      DESKTOP_HOOKCONTROL |
                                      DESKTOP_JOURNALPLAYBACK |
                                      DESKTOP_JOURNALRECORD |
                                      DESKTOP_READOBJECTS |
                                      DESKTOP_SWITCHDESKTOP |
                                      DESKTOP_WRITEOBJECTS |
                                      STANDARD_RIGHTS_REQUIRED,
    }

    public sealed class DesktopAccessRule : AccessRule
    {
        public DesktopAccessRule(IdentityReference identity, DesktopRights desktopRights, AccessControlType type)
            : base(
                identity,
                DesktopAccessRule.AccessMaskFromRights(desktopRights, type),
                false /* isInherited */,
                InheritanceFlags.None,
                PropagationFlags.None,
                type)
        {
        }

        public DesktopRights DesktopRights
        {
            get
            {
                return DesktopAccessRule.RightsFromAccessMask(this.AccessMask);
            }
        }

        internal static DesktopRights RightsFromAccessMask(int accessMask)
        {
            return (DesktopRights)accessMask;
        }

        internal static int AccessMaskFromRights(DesktopRights desktopRights, AccessControlType controlType)
        {
            return (int)desktopRights;
        }
    }

    public sealed class DesktopAuditRule : AuditRule
    {
        public DesktopAuditRule(IdentityReference identity, DesktopRights desktopRights, AuditFlags flags)
            : base(
                identity,
                DesktopAuditRule.AccessMaskFromRights(desktopRights),
                false /* isInherited */,
                InheritanceFlags.None,
                PropagationFlags.None,
                flags)
        {
        }

        public DesktopRights DesktopRights
        {
            get
            {
                return DesktopAuditRule.RightsFromAccessMask(this.AccessMask);
            }
        }

        internal static int AccessMaskFromRights(DesktopRights desktopRights)
        {
            return (int)desktopRights;
        }

        internal static DesktopRights RightsFromAccessMask(int accessMask)
        {
            return (DesktopRights)accessMask;
        }
    }

    public sealed class DesktopSecurity : NativeObjectSecurity
    {
        private readonly Desktop desktop;

        public DesktopSecurity(Desktop desktop, AccessControlSections includeSections)
            : base(false /* isContainer */, ResourceType.WindowObject, desktop, includeSections)
        {
            this.desktop = desktop;
        }

        public override Type AccessRightType
        {
            get
            {
                return typeof(DesktopRights);
            }
        }

        public override Type AccessRuleType
        {
            get
            {
                return typeof(DesktopAccessRule);
            }
        }

        public override Type AuditRuleType
        {
            get
            {
                return typeof(DesktopAuditRule);
            }
        }

        public void AddAccessRule(DesktopAccessRule desktopAccessRule)
        {
            base.AddAccessRule(desktopAccessRule);
        }

        public void AddAuditRule(DesktopAuditRule desktopAuditRule)
        {
            base.AddAuditRule(desktopAuditRule);
        }

        public override AccessRule AccessRuleFactory(
            IdentityReference identityReference,
            int accessMask,
            bool isInherited,
            InheritanceFlags inheritanceFlags,
            PropagationFlags propagationFlags,
            AccessControlType type)
        {
            return new DesktopAccessRule(
                identityReference,
                DesktopAccessRule.RightsFromAccessMask(accessMask),
                type);
        }

        public override AuditRule AuditRuleFactory(
            IdentityReference identityReference,
            int accessMask,
            bool isInherited,
            InheritanceFlags inheritanceFlags,
            PropagationFlags propagationFlags,
            AuditFlags flags)
        {
            return new DesktopAuditRule(
                identityReference,
                DesktopAuditRule.RightsFromAccessMask(accessMask),
                flags);
        }

        public void Commit()
        {
            try
            {
                this.WriteLock();

                AccessControlSections accessControlSectionsFromChanges = this.GetAccessControlSectionsFromChanges();
                this.Persist(this.desktop, accessControlSectionsFromChanges);

                this.AccessRulesModified = false;
                this.AuditRulesModified = false;
                this.GroupModified = false;
                this.OwnerModified = false;
            }
            finally
            {
                this.WriteUnlock();
            }
        }

        public bool RemoveAccessRule(DesktopAccessRule desktopAccessRule)
        {
            return base.RemoveAccessRule(desktopAccessRule);
        }

        public void RemoveAccessRuleAll(DesktopAccessRule desktopAccessRule)
        {
            base.RemoveAccessRuleAll(desktopAccessRule);
        }

        public void RemoveAccessRuleSpecific(DesktopAccessRule desktopAccessRule)
        {
            base.RemoveAccessRuleSpecific(desktopAccessRule);
        }

        public bool RemoveAuditRule(DesktopAuditRule desktopAuditRule)
        {
            return base.RemoveAuditRule(desktopAuditRule);
        }

        public void RemoveAuditRuleAll(DesktopAuditRule desktopAuditRule)
        {
            base.RemoveAuditRuleAll(desktopAuditRule);
        }

        public void RemoveAuditRuleSpecific(DesktopAuditRule desktopAuditRule)
        {
            base.RemoveAuditRuleSpecific(desktopAuditRule);
        }

        public void SetAccessRule(DesktopAccessRule desktopAccessRule)
        {
            base.SetAccessRule(desktopAccessRule);
        }

        public void SetAuditRule(DesktopAuditRule desktopAuditRule)
        {
            base.SetAuditRule(desktopAuditRule);
        }

        private AccessControlSections GetAccessControlSectionsFromChanges()
        {
            return AccessControlSections.None |
                (this.AccessRulesModified ? AccessControlSections.Access : AccessControlSections.None) |
                (this.AuditRulesModified ? AccessControlSections.Audit : AccessControlSections.None) |
                (this.OwnerModified ? AccessControlSections.Owner : AccessControlSections.None) |
                (this.GroupModified ? AccessControlSections.Group : AccessControlSections.None);
        }
    }
}
