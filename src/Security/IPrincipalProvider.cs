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

using System.Collections.Generic;
using System.Security.Principal;

namespace ManagedSandbox.Security
{
    public interface IPrincipalProvider
    {
        /// <summary>
        /// Returns a security descriptor, in SDDL format, that represents the manadtory level SACL.
        /// </summary>
        /// <returns>The mandatory level SACL, in SDDL format.</returns>
        string GetMandatoryLevelSacl();

        /// <summary>
        /// Returns the set of <see cref="SecurityIdentifier"/> instances representing principals that should be given access
        /// to resources in order for the sandboxed process to function.
        /// </summary>
        /// <returns>The set of <see cref="SecurityIdentifier"/> instances.</returns>
        IEnumerable<SecurityIdentifier> GetSecurityIdentifiers();
    }
}
