#pragma once

 
extern "C" NTKERNELAPI CHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

VOID KeSleep(ULONGLONG ulMillSecond)
{
	LARGE_INTEGER li;
	li.QuadPart = -10 * 1000 * ulMillSecond;
	KeDelayExecutionThread(KernelMode, FALSE, &li);
}
