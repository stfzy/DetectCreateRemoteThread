#pragma once

typedef struct _LDR_DATA                         // 24 elements, 0xE0 bytes (sizeof)
{
	struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
	struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
	struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
	VOID*        DllBase;
	VOID*        EntryPoint;
	ULONG32      SizeOfImage;
	UINT8        _PADDING0_[0x4];
	struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
	struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
	ULONG32      Flags;
	UINT16       LoadCount;
	UINT16       TlsIndex;
	union
	{
		struct _LIST_ENTRY HashLinks;
		struct
		{
			VOID*        SectionPointer;
			ULONG32      CheckSum;
			UINT8        _PADDING1_[0x4];
		}_ajjj;
	};

	union
	{
		ULONG32      TimeDateStamp;
		VOID*        LoadedImports;
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	VOID*        PatchInformation;
	struct _LIST_ENTRY ForwarderLinks;
	struct _LIST_ENTRY ServiceTagLinks;
	struct _LIST_ENTRY StaticLinks;
	VOID*        ContextInformation;
	UINT64       OriginalBase;
	union _LARGE_INTEGER LoadTime;
}LDR_DATA, *PLDR_DATA;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
	BOOLEAN ReadImageFileExecOptions;   //
	BOOLEAN BeingDebugged;              //
	BOOLEAN SpareBool;                  //
	HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

	PVOID ImageBaseAddress;
	PVOID Ldr;
	struct _RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
}PEB, *PPEB;
 
extern "C" NTKERNELAPI CHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

extern "C" NTSYSAPI    PPEB  PsGetProcessPeb(IN PEPROCESS Process);

typedef NTSTATUS(__stdcall * ReloadZwQueryVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN ULONG MemoryInformationClass,
	OUT PVOID               Buffer,
	IN ULONG                Length,
	OUT PULONG              ResultLength OPTIONAL
	);

VOID KeSleep(ULONGLONG ulMillSecond)
{
	LARGE_INTEGER li;
	li.QuadPart = -10 * 1000 * ulMillSecond;
	KeDelayExecutionThread(KernelMode, FALSE, &li);
}
