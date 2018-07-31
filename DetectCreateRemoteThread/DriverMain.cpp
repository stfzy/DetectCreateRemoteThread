
#include <ntifs.h>
#include "comm.h"
/*
nt!NtCreateThread:
805c8208 6a28            push    28h
805c820a 68c0ae4d80      push    offset nt!ObWatchHandles+0x674 (804daec0)
805c820f e8fc0cf7ff      call    nt!_SEH_prolog (80538f10)
805c8214 8365fc00        and     dword ptr [ebp-4],0
805c8218 64a124010000    mov     eax,dword ptr fs:[00000124h]
805c821e 8945e0          mov     dword ptr [ebp-20h],eax
805c8221 80b84001000000  cmp     byte ptr [eax+140h],0
805c8228 0f848f000000    je      nt!NtCreateThread+0xb5 (805c82bd)

*/
extern "C" DRIVER_INITIALIZE DriverEntry;
ReloadZwQueryVirtualMemory g_pfn_ZwQueryVirutalMemrory = NULL;
/*
PVOID pre;
BOOLEAN InitNoExportApi()
{
	UNICODE_STRING usApi = { 0 };
	RtlInitUnicodeString(&usApi, L"ZwQueryVirutalMemrory");
	pfn_ZwQueryVirutalMemrory = static_cast<ReloadZwQueryVirtualMemory>(MmGetSystemRoutineAddress(&usApi));
	if (pfn_ZwQueryVirutalMemrory != NULL)
		return TRUE;
	return FALSE;
}*/
// OB_PREOP_CALLBACK_STATUS
// preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
// { 
// 	UNREFERENCED_PARAMETER(RegistrationContext);
// 	if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
// 	{
// 		HANDLE srcPid = PsGetCurrentProcessId();
// 		HANDLE pid = PsGetThreadProcessId((PETHREAD)pOperationInformation->Object);
// 		if (pid != srcPid)
// 		{
// 			DbgBreakPoint();
// 
// 			NTSTATUS status = STATUS_SUCCESS;
// 			HANDLE hProcess = NULL;
// 			PEPROCESS eProcess = PsGetCurrentProcess();
// 
// 			if (NULL == eProcess)
// 				return  OB_PREOP_SUCCESS;
// 
// 			ObReferenceObject(eProcess);
// 
// 			PPEB pPeb = PsGetProcessPeb(eProcess);
// 
// 			if (NULL == pPeb)
// 				return  OB_PREOP_SUCCESS;
// 
// 			status = ObOpenObjectByPointer(eProcess,          // Object    
// 				OBJ_KERNEL_HANDLE,  // HandleAttributes    
// 				NULL,               // PassedAccessState OPTIONAL    
// 				0x0400,       // DesiredAccess    
// 				*PsProcessType,     // ObjectType    
// 				KernelMode,         // AccessMode    
// 				&hProcess
// 			);
// 
// 			if (!NT_SUCCESS(status))
// 			{
// 				KdPrint(("ObOpenObjectByPointer failed:%u \r\n", RtlNtStatusToDosError(status)));
// 				ObDereferenceObject(eProcess);
// 				return  OB_PREOP_SUCCESS;
// 			}
// 
// 			PUNICODE_STRING SectionName = (PUNICODE_STRING)ExAllocatePool(NonPagedPoolNx, 260 * sizeof(WCHAR));
// 			if (NULL == SectionName)
// 			{
// 				ZwClose(hProcess);
// 				ObDereferenceObject(eProcess);
// 				KdPrint(("RExAllocatePool failed \r\n"));
// 				return  OB_PREOP_SUCCESS;
// 			}
// 
// 			memset(SectionName, 0, 260 * sizeof(WCHAR));
// 
// 			PVOID pBaseAddress = NULL;
// 			BOOLEAN bAttach = FALSE;
// 			KAPC_STATE ApcState;
// 			if (eProcess != PsGetCurrentProcess()) {
// 				bAttach = TRUE;
// 				KeStackAttachProcess(eProcess, &ApcState);
// 			}
// 
// 			__try {
// 				pBaseAddress = pPeb->ImageBaseAddress;
// 			}
// 			__except (EXCEPTION_EXECUTE_HANDLER) {
// 				pBaseAddress = NULL;
// 			}
// 
// 			if (bAttach) {
// 				KeUnstackDetachProcess(&ApcState);
// 			}
// 
// 			if (pBaseAddress == NULL)
// 			{
// 				ZwClose(hProcess);
// 				ExFreePool(SectionName);
// 				ObDereferenceObject(eProcess);
// 				KdPrint(("KeUnstackDetachProcess failed \r\n"));
// 				return  OB_PREOP_SUCCESS;
// 			}
// 
// 
// 			SIZE_T ReturnLength = 0;
// 			status = pfn_ZwQueryVirutalMemrory(
// 				hProcess,
// 				pBaseAddress,
// 				2,
// 				SectionName,
// 				260 * sizeof(WCHAR),
// 				&ReturnLength
// 			);
// 
// 			if (!NT_SUCCESS(status)) {
// 				if (status == STATUS_INFO_LENGTH_MISMATCH) {
// 					DbgPrint("Length IS NOT ENGOUTH !!! \r\n");
// 				}
// 
// 				ExFreePool(SectionName);
// 				ZwClose(hProcess);
// 				ObDereferenceObject(eProcess);
// 				return  OB_PREOP_SUCCESS;
// 			}
// 
// 			if (!NT_SUCCESS(status))
// 			{
// 				KdPrint(("SectionName Get Failed  \r\n"));
// 				ExFreePool(SectionName);
// 				ZwClose(hProcess);
// 				ObDereferenceObject(eProcess);
// 				return  OB_PREOP_SUCCESS;
// 			}
// 			ANSI_STRING as = { 0 };
// 			status = RtlUnicodeStringToAnsiString(&as, SectionName, TRUE);
// 			if (!NT_SUCCESS(status))
// 			{
// 				KdPrint(("RtlUnicodeStringToAnsiString Failed  \r\n"));
// 				ExFreePool(SectionName);
// 				ZwClose(hProcess);
// 				ObDereferenceObject(eProcess);
// 				return  OB_PREOP_SUCCESS;
// 			}
// 
// 			DbgPrint(
// 				"DetectCreateRemoteThread >>ProcPath:%Z SrcPid:%p DstPid:%p Tid:%p bCreate:%d \r\n",
// 				&as,
// 				srcPid,
// 				pid,
// 				0,
// 				1
// 			);
// 
// 			OBJECT_ATTRIBUTES oa;
// 			InitializeObjectAttributes(&oa, NULL, 0, 0, 0);
// 			//		HANDLE hProcessHanle = NULL;
// 		 
// 
// 
// 
// 			UNICODE_STRING usPattern = { 0 };
// 			RtlInitUnicodeString(&usPattern, L"*REMOTEDLL*");
// 
// 			if (FsRtlIsNameInExpression(&usPattern, SectionName, TRUE, 0))
// 			{
// 				DbgBreakPoint(); 
//  
// 			}
// 			RtlFreeAnsiString(&as);
// 			ExFreePool(SectionName);
// 			ZwClose(hProcess);
// 			ObDereferenceObject(eProcess);
// 			 
// 
// 		} 
// 	}
// 	return OB_PREOP_SUCCESS;
// }

/*
void ThreadProcedure(PVOID ParameterData)
{
	HANDLE hThreadId = (HANDLE)ParameterData;
	PETHREAD eThread = NULL;
	
	while (true)
	{
		PsLookupThreadByThreadId(hThreadId, &eThread);
		if (eThread)
		{
			__asm
			{
				push 0
				push eThread
				mov ecx, 0x805c9b02
				call ecx

			}
			break;
		} 
		KeSleep(10);
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}*/
 
 PVOID  GetZwQueryVirtualMemoryAddress() noexcept
 {
	   
	PUCHAR ulSearchStart = NULL;
 

	/*
	lkd> u ZwQueryVirtualMemory
	nt!ZwQueryVirtualMemory:
	804ffb90 b8b2000000      mov     eax,0B2h
	804ffb95 8d542404        lea     edx,[esp+4]
	804ffb99 9c              pushfd
	804ffb9a 6a08            push    8
	804ffb9c e8f0e80300      call    nt!KiSystemService (8053e491)
	804ffba1 c21800          ret     18h
	nt!ZwQueryVolumeInformationFile:                 <------------------从这里一直往上减，当Index一样的时候，就是地址了。
	804ffba4 b8b3000000      mov     eax,0B3h
	804ffba9 8d542404        lea     edx,[esp+4]
	*/
	
	// Only do one test on Windows XP SP3 
	__try
	{
		ulSearchStart = reinterpret_cast<PUCHAR>(ZwQueryVolumeInformationFile);
		return reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ulSearchStart) - 0x14);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	} 
}
/*

VOID CreateThreadNotifyRoutine(
	IN HANDLE  ProcessId,
	IN HANDLE  ThreadId,
	IN BOOLEAN  Create
)
{ 
	HANDLE hCurrProcessId = PsGetCurrentProcessId();
	 
	
	if (ProcessId>(HANDLE)8 && ProcessId != hCurrProcessId )
	{ 
		NTSTATUS status = STATUS_SUCCESS; 
		HANDLE hProcess = NULL;
		PEPROCESS eProcess = PsGetCurrentProcess();
		
		if (NULL == eProcess)
			return;

		ObReferenceObject(eProcess);

		PPEB pPeb =  PsGetProcessPeb(eProcess);

		if (NULL == pPeb)
			return;

		status = ObOpenObjectByPointer(eProcess,          // Object    
			OBJ_KERNEL_HANDLE,  // HandleAttributes    
			NULL,               // PassedAccessState OPTIONAL    
			0x0400,       // DesiredAccess    
			*PsProcessType,     // ObjectType    
			KernelMode,         // AccessMode    
			&hProcess
		);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("ObOpenObjectByPointer failed:%u \r\n",RtlNtStatusToDosError(status)));
			ObDereferenceObject(eProcess);
			return;
		}

		PUNICODE_STRING SectionName = (PUNICODE_STRING)ExAllocatePool(NonPagedPoolNx, 260 * sizeof(WCHAR));
		if (NULL == SectionName)
		{
			ZwClose(hProcess);
			ObDereferenceObject(eProcess);
			KdPrint(("RExAllocatePool failed \r\n"));
			return;
		}

		memset(SectionName, 0, 260 * sizeof(WCHAR));

		PVOID pBaseAddress = NULL;
		BOOLEAN bAttach = FALSE;
		KAPC_STATE ApcState;
		if (eProcess != PsGetCurrentProcess()) {
			bAttach = TRUE;
			KeStackAttachProcess(eProcess, &ApcState);
		}

		__try {
			pBaseAddress = pPeb->ImageBaseAddress;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			pBaseAddress = NULL;
		}

		if (bAttach) {
			KeUnstackDetachProcess(&ApcState);
		}
		
		if (pBaseAddress == NULL)
		{
			ZwClose(hProcess);
			ExFreePool(SectionName);
			ObDereferenceObject(eProcess);
			KdPrint(("KeUnstackDetachProcess failed \r\n"));
			return;
		}


		SIZE_T ReturnLength = 0;
		status = pfn_ZwQueryVirutalMemrory(
			hProcess,
			pBaseAddress,
			2,
			SectionName,
			260 * sizeof(WCHAR),
			&ReturnLength
		);

		if (!NT_SUCCESS(status)) {
			if (status == STATUS_INFO_LENGTH_MISMATCH) {
				DbgPrint("Length IS NOT ENGOUTH !!! \r\n");
			}

			ExFreePool(SectionName);
			ZwClose(hProcess);
			ObDereferenceObject(eProcess);
			return;
		}

		if (!NT_SUCCESS(status))
		{
			KdPrint(("SectionName Get Failed  \r\n")); 
			ExFreePool(SectionName);
			ZwClose(hProcess);
			ObDereferenceObject(eProcess);
			return;
		} 
		ANSI_STRING as = { 0 };
		status = RtlUnicodeStringToAnsiString(&as, SectionName, TRUE);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("RtlUnicodeStringToAnsiString Failed  \r\n"));
			ExFreePool(SectionName);
			ZwClose(hProcess);
			ObDereferenceObject(eProcess);
			return;
		}
		
		DbgPrint(
			"DetectCreateRemoteThread >>ProcPath:%Z SrcPid:%p DstPid:%p Tid:%p bCreate:%d \r\n",
			&as,
			hCurrProcessId, 
			ProcessId, 
			ThreadId, 
			Create ? 1 : 0
		);

		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, NULL, 0, 0, 0);
//		HANDLE hProcessHanle = NULL;
		CLIENT_ID ClientId = { 0 };
		 
		ClientId.UniqueProcess = hCurrProcessId; 
		ClientId.UniqueThread = 0;

		
	 
		UNICODE_STRING usPattern = { 0 }; 
		RtlInitUnicodeString(&usPattern, L"*REMOTEDLL*");

		if (FsRtlIsNameInExpression(&usPattern, SectionName, TRUE, 0))
		{
			DbgBreakPoint();
			CLIENT_ID       ClientID = { 0 };
			HANDLE ThreadHandle = NULL;
			OBJECT_ATTRIBUTES ObjectAttributes;
			InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
			 
				status = PsCreateSystemThread(&ThreadHandle,0,0,NtCurrentProcess(),&ClientID,(PKSTART_ROUTINE)ThreadProcedure,(PVOID)ThreadId);

// 				805c9ed1 ff7508          push    dword ptr[ebp + 8]
// 				805c9ed4 50              push    eax
// 				805c9ed5 e828fcffff      call    nt!PspTerminateThreadByPointer(805c9b02)
			
// 			ZwOpenProcess(&hProcessHanle, GENERIC_ALL, &oa, &ClientId);
// 			if (hProcessHanle)
// 				ZwTerminateProcess(hProcessHanle, 0);
		}
		RtlFreeAnsiString(&as);
		ExFreePool(SectionName);
		ZwClose(hProcess);
		ObDereferenceObject(eProcess);
		 
	}

}*/
typedef
NTSTATUS
(NTAPI*
	pfn_NtCreateThread)(
		OUT PHANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN HANDLE ProcessHandle,
		OUT PCLIENT_ID ClientId,
		IN PCONTEXT ThreadContext,
		IN PVOID UserStack,
		IN BOOLEAN CreateSuspended
		);
pfn_NtCreateThread g_pfnOrgNtCreateThread = NULL;
_Function_class_(DRIVER_UNLOAD)
VOID DriverUnload(
	_In_ struct _DRIVER_OBJECT *DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	*(PULONG)0x80502c60 = reinterpret_cast<ULONG>(g_pfnOrgNtCreateThread);
	//ObUnRegisterCallbacks(pre);
	//PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
}

int StGetProcessFullPathByObject(PEPROCESS pEprocess,PUNICODE_STRING & pProcessPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hProcess = NULL;
	PVOID  pBaseAddress = NULL;
	BOOLEAN bAttach = FALSE;
	KAPC_STATE ApcState = {};
	int iRet = 0;

	if (NULL == pEprocess )
		return 1;
	
	// First reference the object
	ObReferenceObject(pEprocess);

	// Get PEB
	PPEB pPeb = PsGetProcessPeb(pEprocess);

	
	if (NULL == pPeb )
	{
		iRet = 2;
		goto _OPEN_OBJECT_FAILED;
	}

	// Get process handle 
	status = ObOpenObjectByPointer(
		pEprocess,               
		OBJ_KERNEL_HANDLE,    
		NULL,                
		0x0400,				 
		*PsProcessType,     
		KernelMode,         
		&hProcess
	);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("ObOpenObjectByPointer failed:%u \r\n", RtlNtStatusToDosError(status)));
		iRet = 3;
		goto _OPEN_OBJECT_FAILED;
		 
	}

	pProcessPath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPoolNx, 260 * sizeof(WCHAR),'STPH');
	 

	if (NULL == pProcessPath)
	{ 
		KdPrint(("ExAllocatePool failed \r\n"));
		iRet = 4;
		goto _ALLOC_MEM_FAILED;
	}

	memset(pProcessPath, 0, 260 * sizeof(WCHAR));
	  
	
	if (pEprocess != PsGetCurrentProcess()) {
		bAttach = TRUE;
		KeStackAttachProcess(pEprocess, &ApcState);
	}

	__try {
		pBaseAddress = pPeb->ImageBaseAddress;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		pBaseAddress = NULL;
	}

	if (bAttach) {
		KeUnstackDetachProcess(&ApcState);
		bAttach = FALSE;
	}

	  
	if (pBaseAddress == NULL)
	{ 
		KdPrint(("KeUnstackDetachProcess failed \r\n"));
		iRet = 5;
		goto _ALL_FAILED;
	}
	 
	SIZE_T ReturnLength = 0;
	if (NULL == g_pfn_ZwQueryVirutalMemrory)
	{
		iRet = 6;
		goto _ALL_FAILED;
	}
	status = g_pfn_ZwQueryVirutalMemrory(
		hProcess,
		pBaseAddress,
		2,
		pProcessPath,
		260 * sizeof(WCHAR),
		&ReturnLength
	);
	  
	if (!NT_SUCCESS(status))
	{
		KdPrint(("SectionName Get Failed  \r\n")); 
		iRet = 7; 
		goto _ALL_FAILED;
	}

	goto _ALLOC_MEM_FAILED;

_ALL_FAILED:
	ExFreePool(pProcessPath);
	pProcessPath = NULL;
_ALLOC_MEM_FAILED:
	ZwClose(hProcess);
_OPEN_OBJECT_FAILED:
	ObDereferenceObject(pEprocess);

	return 0;
}

NTSTATUS
NTAPI MyNtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PVOID UserStack,
	IN BOOLEAN CreateSuspended
)
{
	BOOLEAN  bDeny			      = FALSE;  
	PVOID    pDstProcessObject    = NULL;
	PVOID    pCurrentProcessObjet = NULL;
	// Get dst process obj from handle
	NTSTATUS status				  = ObReferenceObjectByHandle(
																ProcessHandle, 
																GENERIC_ALL, 
																*PsProcessType, 
																KernelMode, 
																&pDstProcessObject, 
																NULL
															 );
	// If get EPROCESS successed 
	if (NT_SUCCESS(status))
	{
		// Get current process obj 
		pCurrentProcessObjet = PsGetCurrentProcess(); 

		// Only make a deal when curr pro obj not equal dst pro obj
		if (pCurrentProcessObjet != pDstProcessObject)
		{
			UNICODE_STRING usPattern = { 0 };
			do
			{ 
				// Get current process path and dest process path
				// If any one get failed , break
				PUNICODE_STRING pUsCurrProcessPath = NULL, pUsDstProcessPath = NULL;
				int iRet = StGetProcessFullPathByObject((PEPROCESS)pCurrentProcessObjet, pUsCurrProcessPath);
				if (iRet != 0 || !MmIsAddressValid(pUsCurrProcessPath))
					break;

				iRet = StGetProcessFullPathByObject((PEPROCESS)pDstProcessObject, pUsDstProcessPath);
				if (iRet != 0 || !MmIsAddressValid(pUsDstProcessPath))
				{
					ExFreePool(pUsCurrProcessPath);
					pUsCurrProcessPath = NULL;
					break;
				}
				 
				ANSI_STRING asCurrentProcessPath = { 0 };
				ANSI_STRING asDstProcessPath = { 0 };

				// Convert from unicode string to ansi string  
				status = RtlUnicodeStringToAnsiString(&asCurrentProcessPath, pUsCurrProcessPath, TRUE);
				if (!NT_SUCCESS(status))
				{
					goto _ANSI_FIRST_FAILED;
				}

				status = RtlUnicodeStringToAnsiString(&asDstProcessPath, pUsDstProcessPath, TRUE);
				if (!NT_SUCCESS(status))
				{
					goto _ANSI_SECOND_FAILED;  
				}

				KdPrint((
					"DetectCreateRemoteThread >>Process [%Z]  CREATE REMOTE THREAD IN Process [%Z]  \r\n",
					&asCurrentProcessPath,
					&asDstProcessPath					 
				));
				 
				
				RtlInitUnicodeString(&usPattern, L"*REMOTEDLL*");

				if (FsRtlIsNameInExpression(&usPattern, pUsCurrProcessPath, TRUE, 0))
				{
					bDeny = TRUE;
				}


				RtlFreeAnsiString(&asDstProcessPath);
			_ANSI_SECOND_FAILED:
				RtlFreeAnsiString(&asCurrentProcessPath);
				
			_ANSI_FIRST_FAILED:
				ExFreePool(pUsCurrProcessPath);
				ExFreePool(pUsDstProcessPath); 
			} while (FALSE);
		}

		ObDereferenceObject(pDstProcessObject);
	}

	if (bDeny)
		return STATUS_MEDIA_WRITE_PROTECTED;

	if (g_pfnOrgNtCreateThread)
		return g_pfnOrgNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, UserStack, CreateSuspended);
	
	return STATUS_NOT_IMPLEMENTED;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);
 
//  	if (!InitNoExportApi())
//  		return STATUS_UNSUCCESSFUL;

	// Get ZwQueryVirutalMemrory Routine Address
	g_pfn_ZwQueryVirutalMemrory = static_cast<ReloadZwQueryVirtualMemory>(GetZwQueryVirtualMemoryAddress());
	
	// Restore the original NtCreateThread routine address
	g_pfnOrgNtCreateThread = reinterpret_cast<pfn_NtCreateThread>((*(PULONG)0x80502c60)); // 仅测试用，直接拿NtCreateThread在SSDT表中的位置来替换
	*(PULONG)0x80502c60 = reinterpret_cast<ULONG>(MyNtCreateThread);
	
	// Print the addresses after exchange the address
	KdPrint(("DetectCreateRemoteThread: Org_NtCreateThread : %p Cur_NtCreateThread : %p \r\n", 
		g_pfnOrgNtCreateThread, 
		MyNtCreateThread));

	// Support unload
	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
	 	
 	//return PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
}

 
//OB_CALLBACK_REGISTRATION obReg;
//OB_OPERATION_REGISTRATION opReg;


//PLDR_DATA ldr;

// 绕过MmVerifyCallbackFunction。
//ldr = (PLDR_DATA)pDriverObject->DriverSection;
//ldr->Flags |= 0x20;

// 	memset(&obReg, 0, sizeof(obReg));
// 	obReg.Version = OB_FLT_REGISTRATION_VERSION;
// 	obReg.OperationRegistrationCount = 1;
// 	obReg.RegistrationContext = NULL;
// 	RtlInitUnicodeString(&obReg.Altitude, L"321000");
// 	memset(&opReg, 0, sizeof(opReg)); //初始化结构体变量

//下面请注意这个结构体的成员字段的设置
// 	opReg.ObjectType = PsThreadType;
// 	opReg.Operations = OB_OPERATION_HANDLE_CREATE ;
//
// 	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall; //在这里注册一个回调函数指针
//
// 	obReg.OperationRegistration = &opReg; //注意这一条语句

// return ObRegisterCallbacks(&obReg, &pre); //在这里注册回调函数
 