;
; Copyright (C) 2019 Assured Information Security, Inc.
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

bits 64
default rel

section .text

    global sse_test
sse_test:

    mov rax, rdi
    push rax
    push rax

    movups xmm0, [rsp]

    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1
    movups xmm1, xmm0
    movups xmm0, xmm1

    movups [rsp], xmm0

    pop rax
    pop rax

    ret
