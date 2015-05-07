#pragma once
#include "struct.h"
#include "UtilityFunc.h"
#include "KernelReload.h"

typedef struct _SERVICE_FUNCTION_ADDR{
	ULONG dwNtReadVirtualMemory;
	ULONG dwReloadNtReadVirtualMemory;
	//
	ULONG dwNtWriteVirtualMemory;
	ULONG dwReloadNtWriteVirtualMemory;
	//
	ULONG dwNtOpenProcess;
	ULONG dwReloadNtOpenProcess;
	//
	ULONG dwNtCreateThread;
	ULONG dwReloadNtCreateThread;
	//
	ULONG dwNtCreateProcess;
	ULONG dwReloadNtCreateProcess;
	//
	ULONG dwNtCreateProcessEx;
	ULONG dwReloadNtCreateProcessEx;
	//
	ULONG dwNtSuspendThread;
	ULONG dwReloadNtSuspendThread;
	//
	ULONG dwNtSuspendProcess;
	ULONG dwReloadNtSuspendProcess;
	//
	ULONG dwNtLoadDriver;
	ULONG dwReloadNtLoadDriver;
	//
	ULONG dwNtSetSystemInformation;
	ULONG dwReloadNtSetSystemInformation;
	//
	ULONG dwNtTerminateProcess;
	ULONG dwReloadNtTerminateProcess;
	//
	ULONG dwNtTerminateThread;
	ULONG dwReloadNtTerminateThread;
	//
	ULONG dwNtCreateFile;
	ULONG dwReloadNtCreateFile;
}SERVICE_FUNCTION_ADDR,*PSERVICE_FUNCTION_ADDR;

typedef struct _KERNEL_FUNCTION_INFO{
	//
	//ULONG dwPspTerminateProcess;
	//ULONG dwReloadPspTerminateProcess;
	//
	ULONG dwPspTerminateThreadByPointer;
	ULONG dwReloadPspTerminateThreadByPointer;
	//
	ULONG dwKeStackAttachProcess;
	ULONG dwReloadKeStackAttachProcess;
	//
	ULONG dwKeUnstackDetachProcess;
	ULONG dwReloadKeUnstackDetachProcess;

}KERNEL_FUNCTION_INFO,*PKERNEL_FUNCTION_INFO;
BOOL GetNtosInformation(KERNEL_MODULE_INFO *pNtosInfo);
NTSTATUS ReloadNtos(PDRIVER_OBJECT   DriverObject);
VOID FreeReloadNtosPool();