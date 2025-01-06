

.data
	;structaddr dq 0h
	
	
.code
	ALIGN 16
	asm_syscall proc
		mov rax,[rcx + 8h]
		mov r10,[rcx + 10h]	
		db 44h
		mov rcx,[rcx]
		db 44h
		not rcx
		jmp rcx
		int 3h
		int 3h
		dd 0CCCCCCCCh
		dq 0CCCCCCCCCCCCCCCCh
	asm_syscall endp

	ALIGN 16
	asm_fakestack proc
		push rax
		mov rax, rsp
		lea rsp, [rsp-0680h]
		xchg [rsp], rbp
		sub rsp, 8h
		mov [rsp], rax
		push [rax]
		mov [rax], ebp
		lea rax, [rax+08h]
		movaps xmm0, [rax+30h]
		movaps [rsp+28h], xmm0
		movaps xmm0, [rax+40h]
		movaps [rsp+38h], xmm0
		movaps xmm0, [rax+50h]
		movaps [rsp+48h], xmm0
		movaps xmm0, [rax+60h]
		movaps [rsp+58h], xmm0
		dd 408748h
		db 44h
		not rcx
		jmp rcx
		int 3h
		int 3h
	asm_fakestack endp

	

end
