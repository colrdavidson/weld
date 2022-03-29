bits 64

section .text

global _start
extern __main

_start:
	xor rbp, rbp
	pop rdi
	mov rsi, rsp
	push rax
	and rsp, -16
	call __main
