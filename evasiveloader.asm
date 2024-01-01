
.data
	wSystemCall DWORD 000h
	randomSyscallAddress	QWORD	000h

.code

	setssnsyscall proc	
		xor eax, eax					; eax = 0
		mov wSystemCall, eax			; wSystemCall = 0
		mov randomSyscallAddress, rax		; qSyscallInsAdress = 0
		mov eax, ecx					; eax = ssn
		mov wSystemCall, eax			; wSystemCall = eax = ssn
		mov r8, rdx						; r8 = AddressOfASyscallInst
		mov randomSyscallAddress, r8		; qSyscallInsAdress = r8 = AddressOfASyscallInst
		ret
	setssnsyscall endp

	launchCode proc
		xor r10, r10						; r10 = 0
		mov rax, rcx						; rax = rcx
		mov r10, rax						; r10 = rax	= rcx
		mov eax, wSystemCall				; eax = ssn
		jmp Run								; execute 'Run'
		xor eax, eax	; wont run
		xor rcx, rcx	; wont run
		shl r10, 2		; wont run
	Run:
		jmp qword ptr [randomSyscallAddress]
		xor r10, r10					; r10 = 0
		mov randomSyscallAddress, r10		; randomSyscallAddress = 0
		ret
	launchCode endp

end
