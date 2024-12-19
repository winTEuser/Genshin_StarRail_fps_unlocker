

.data
	sc_number dd 0h
	sys_call_addr dq 0h
	
.code
	ALIGN 16
	asm_initsc proc
		mov sc_number, ecx
		ret
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
	asm_initsc endp

	asm_initaddr proc
		db 44h
		mov sys_call_addr, rcx
		ret
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
	asm_initaddr endp

	ALIGN 16
	asm_syscall proc
		mov eax, sc_number
		mov r10, rcx
		db 48h
		jmp [sys_call_addr]
		int 3h
		int 3h
	asm_syscall endp

end
