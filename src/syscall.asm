
.code
	ALIGN 16
	asm_syscall proc
		db 048h
		push [rcx + 8h]
		mov r10,[rcx + 10h]	
		dd 0498B48h
		db 44h
		lea rax, callreturn
		push rax
		mov rax, rsp
		lea rsp, [rsp-0680h]
		xchg [rsp], rbp
		sub rsp, 8h
		mov [rsp], rax
		lea rsp, [rsp-0120h]
		push [rax]
		mov [rax], ebp
		lea rax, [rax+08h]
		movups xmm0, [rax+30h]
		movups [rsp+28h], xmm0
		movups xmm0, [rax+40h]
		movups [rsp+38h], xmm0
		movups xmm0, [rax+50h]
		movups [rsp+48h], xmm0
		movups xmm0, [rax+60h]
		movups [rsp+58h], xmm0
		dd 408748h
		db 44h
		not rcx
		jmp rcx
		int 3h
		int 3h
		dd 0CCCCCCCCh
		dq 0CCCCCCCCCCCCCCCCh
		dq 0CCCCCCCCCCCCCCCCh

	ALIGN 16
	callreturn:
		lea rsp, [rsp-0100h]
		lea rsp, [rsp+0220h]
		xchg [rsp], rax
		xchg rsp, rax
		mov rbp, [rax+08h]
		dd 0408B48h
		add rsp, 10h
		ret
		int 3h
	asm_syscall endp

end
