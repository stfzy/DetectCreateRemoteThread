#include <ntddk.h>
#include "comm.h"

extern "C" DRIVER_INITIALIZE DriverEntry;

VOID CreateThreadNotifyRoutine(
	IN HANDLE  ProcessId,
	IN HANDLE  ThreadId,
	IN BOOLEAN  Create
)
{ 
	HANDLE hCurrProcessId = PsGetCurrentProcessId();
	
	if (ProcessId != hCurrProcessId)
	{
		CHAR * pCurrProcessName = NULL;
		PEPROCESS pCurrEprocess = IoGetCurrentProcess();
		if (pCurrEprocess)
			pCurrProcessName = PsGetProcessImageFileName(pCurrEprocess);

		size_t stPathLen = 0;
		const CHAR* pTemp = pCurrProcessName;
		if (pTemp)
			stPathLen = strlen(pTemp);

		for (size_t i = 0; i < stPathLen; i++)
		{
			DbgPrint("%02x ", pTemp[i]);
		}
		  
			
		DbgPrint("\r\n");


		ANSI_STRING asProcessName = {0};
		RtlInitAnsiString(&asProcessName, pCurrProcessName == NULL ? "NULL" : (const char *)pCurrProcessName);
		DbgPrint(
			"DetectCreateRemoteThread >>ProcPath:%Z SrcPid:%p DstPid:%p Tid:%p bCreate:%d \r\n",
			&asProcessName,
			hCurrProcessId, 
			ProcessId, 
			ThreadId, 
			Create ? 1 : 0
		);
		 
	}

}
_Function_class_(DRIVER_UNLOAD)
VOID 
DriverUnload(
	_In_ struct _DRIVER_OBJECT *DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);
 
	pDriverObject->DriverUnload = DriverUnload;
	return PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
}