

.data
	psc_number dq 0h
	
	
.code
	asm_initpsc proc
	    db 44h
		mov psc_number, rcx
		ret
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
		int 3h
	asm_initpsc endp

	ALIGN 16
	asm_syscall proc
		mov rax, psc_number
		test rax,rax
		je err
		mov eax, dword ptr [rax]
		mov r10, rcx
		db 48h
		dd 0b8481F0Fh
		syscall
		cdqe
		ret
		int 3h
		int 3h

	err:
		mov eax, 0C0000005h
		ret
		int 3h
	asm_syscall endp

end
