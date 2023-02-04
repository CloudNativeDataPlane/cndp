/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */
/*
 * https://github.com/halayli/lthread which carries the following license.
 *
 * Copyright (c) 2012, Hasan Alayli <halayli@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(__x86_64__)
__asm__(".text\n"
        ".p2align 4,,15\n"
        ".globl cthread_switch\n"
        ".globl _cthread_switch\n"
        "cthread_switch:\n"
        "_cthread_switch:\n"
        "	movq %rsp, 0(%rsi)	# save stack_pointer\n"
        "	movq %rbp, 8(%rsi)	# save frame_pointer\n"
        "	movq (%rsp), %rax	# save insn_pointer\n"
        "	movq %rax, 16(%rsi)\n"
        "	movq %rbx, 24(%rsi)\n	# save rbx,r12-r15\n"
        "	movq 24(%rdi), %rbx\n"
        "	movq %r15, 56(%rsi)\n"
        "	movq %r14, 48(%rsi)\n"
        "	movq 48(%rdi), %r14\n"
        "	movq 56(%rdi), %r15\n"
        "	movq %r13, 40(%rsi)\n"
        "	movq %r12, 32(%rsi)\n"
        "	movq 32(%rdi), %r12\n"
        "	movq 40(%rdi), %r13\n"
        "	movq 0(%rdi), %rsp	# restore stack_pointer\n"
        "	movq 16(%rdi), %rax	# restore insn_pointer\n"
        "	movq 8(%rdi), %rbp	# restore frame_pointer\n"
        "	movq %rax, (%rsp)\n"
        "	ret\n");
#else /* if defined(__x86_64__) */
#pragma GCC error "__x86_64__ is not defined"
#endif /* if defined(__x86_64__) */
