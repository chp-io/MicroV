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

%define VMCS_GUEST_RSP 0x0000681C
%define VMCS_GUEST_RIP 0x0000681E

global vmcs_launch:function

section .text

; Launch VMCS
;
; Launch the execution of a VMCS. Note that this function should not return.
; If it does, an error has occurred.
;
vmcs_launch:

    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov rsi, VMCS_GUEST_RSP
    vmwrite rsi, [rdi + 0x080]
    mov rsi, VMCS_GUEST_RIP
    vmwrite rsi, [rdi + 0x078]

    ; Load xsave_info address
    mov r12, [rdi + 0x0A8]
    push r12

    ; Store current state to the host area
    mov rax, [r12 + 0x10]
    mov rdx, [r12 + 0x10]
    shr rdx, 32
    xor rcx, rcx
    xsetbv
    mov rcx, [r12 + 0x00]
    xsave [rcx]

    ; Load state from the guest area
    mov rax, [r12 + 0x18]
    mov rdx, [r12 + 0x18]
    shr rdx, 32
    xor rcx, rcx
    xsetbv
    mov rcx, [r12 + 0x08]
    xrstor [rcx]

    mov r15, [rdi + 0x070]
    mov r14, [rdi + 0x068]
    mov r13, [rdi + 0x060]
    mov r12, [rdi + 0x058]
    mov r11, [rdi + 0x050]
    mov r10, [rdi + 0x048]
    mov r9,  [rdi + 0x040]
    mov r8,  [rdi + 0x038]
    mov rsi, [rdi + 0x028]
    mov rbp, [rdi + 0x020]
    mov rdx, [rdi + 0x018]
    mov rcx, [rdi + 0x010]
    mov rbx, [rdi + 0x008]
    mov rax, [rdi + 0x000]

    mov rdi, [rdi + 0x030]

    vmlaunch

    ; Store state to the guest area
    pop r12
    mov rax, [r12 + 0x18]
    mov rdx, [r12 + 0x18]
    shr rdx, 32
    mov rcx, [r12 + 0x08]
    xsave [rcx]

    ; Load state from the host area
    mov rax, [r12 + 0x10]
    mov rdx, [r12 + 0x10]
    shr rdx, 32
    xor rcx, rcx
    xsetbv
    mov rcx, [r12 + 0x00]
    xrstor [rcx]

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx

; We should never get this far. If we do, it's because the launch failed. If
; happens, we return so that we can throw an exception and tell the user that
; something really bad happened.

    ret
