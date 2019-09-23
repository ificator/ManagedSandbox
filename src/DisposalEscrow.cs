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

namespace ManagedSandbox
{
    public class DisposalEscrow : IDisposable
    {
        private readonly IList<IDisposable> disposables = new List<IDisposable>();

        public void Add(IDisposable disposable)
        {
            this.disposables.Add(disposable);
        }

        public void Add(IEnumerable<IDisposable> disposables)
        {
            foreach (IDisposable disposable in disposables)
            {
                this.disposables.Add(disposable);
            }
        }

        public void Dispose()
        {
            foreach (IDisposable disposable in this.disposables)
            {
                disposable.Dispose();
            }

            this.Reset();
        }

        public void Reset()
        {
            this.disposables.Clear();
        }

        public void Subsume(DisposalEscrow disposalEscrow)
        {
            this.Add(disposalEscrow.disposables);
            disposalEscrow.Reset();
        }
    }
}
