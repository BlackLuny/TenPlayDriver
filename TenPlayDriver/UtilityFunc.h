#pragma once
#include "struct.h"
#include "GameInfo.h"
#include "WindowsVersion.h"
#define		NEWLINE				"\n"
//////////////////////////////////////////////////////////////////////////
#define _AVDBG_
#ifdef _AVDBG_
#define DbgPrintEx( _x_ )  DbgPrint( _x_ )
#define avPrint( _x_ )  DbgPrint( _x_ ## NEWLINE)

#else
#define avPrint( _x_ )
#define DbgPrintEx( _x_ )
#endif
//////////////////////////////////////////////////////////////////////////
//ZwQueryInformationProcess
typedef NTSTATUS	(__stdcall *PFN_ZWQUERYINFORMATIONPROCESS)(
	IN       HANDLE ProcessHandle,
	IN       PROCESSINFOCLASS ProcessInformationClass,
	OUT      PVOID ProcessInformation,
	IN       ULONG ProcessInformationLength,
	  PULONG ReturnLength
	);

//////////////////////////////////////////////////////////////////////////
//声明内核函数使用
NTKERNELAPI VOID KeSetSystemAffinityThread (KAFFINITY Affinity);  
NTKERNELAPI VOID KeRevertToUserAffinityThread (VOID);
NTKERNELAPI
	NTSTATUS
	SeCreateAccessState(
	PACCESS_STATE AccessState,
	PAUX_ACCESS_DATA AuxData,
	ACCESS_MASK DesiredAccess,
	PGENERIC_MAPPING GenericMapping
	);

NTKERNELAPI
	VOID
	SeDeleteAccessState(
	PACCESS_STATE AccessState
	);
NTKERNELAPI				
	NTSTATUS
	ObCreateObject(
	IN KPROCESSOR_MODE ProbeMode,
	IN POBJECT_TYPE ObjectType,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN KPROCESSOR_MODE OwnershipMode,
	IN OUT PVOID ParseContext OPTIONAL,
	IN ULONG ObjectBodySize,
	IN ULONG PagedPoolCharge,
	IN ULONG NonPagedPoolCharge,
	OUT PVOID *Object
	);
NTKERNELAPI                                                     
	NTSTATUS                                                        
	ObReferenceObjectByHandle(                                      
	IN HANDLE Handle,                                           
	IN ACCESS_MASK DesiredAccess,                               
	IN POBJECT_TYPE ObjectType OPTIONAL,                        
	IN KPROCESSOR_MODE AccessMode,                              
	OUT PVOID *Object,                                          
	OUT POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL   
	);                                                          
NTKERNELAPI                                                     
	NTSTATUS                                                        
	ObOpenObjectByPointer(                                          
	IN PVOID Object,                                            
	IN ULONG HandleAttributes,                                  
	IN PACCESS_STATE PassedAccessState OPTIONAL,                
	IN ACCESS_MASK DesiredAccess OPTIONAL,                      
	IN POBJECT_TYPE ObjectType OPTIONAL,                        
	IN KPROCESSOR_MODE AccessMode,                              
	OUT PHANDLE Handle                                          
	); 
NTKERNELAPI
	NTSTATUS
	ObReferenceObjectByName(
	IN PUNICODE_STRING ObjectName,
	IN ULONG Attributes,
	IN PACCESS_STATE PassedAccessState OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	IN POBJECT_TYPE ObjectType,
	IN KPROCESSOR_MODE AccessMode,
	IN OUT PVOID ParseContext OPTIONAL,
	OUT PVOID *Object
	);
NTSTATUS __stdcall  ZwQuerySystemInformation(
	__in       ULONG SystemInformationClass,
	__inout    PVOID SystemInformation,
	__in       ULONG SystemInformationLength,
	__out_opt  PULONG ReturnLength
	);
NTKERNELAPI
	VOID
	KeAttachProcess (
	PEPROCESS Process
	);

NTKERNELAPI
	VOID
	KeDetachProcess (
	VOID
	);
PCHAR PsGetProcessImageFileName(PEPROCESS eprocess);
NTKERNELAPI
	PEPROCESS
	IoThreadToProcess(
	IN PETHREAD Thread
	);
//
NTSTATUS PsLookupProcessByProcessId(
	HANDLE ProcessId,
	PEPROCESS *Process
	);
//////////////////////////////////////////////////////////////////////////
VOID WProtectOff();

VOID WProtectOn();

PVOID GetExortedFunctionAddress(PWCHAR FunctionName);
BOOL MmIsAddressValidEx(
	IN PVOID Pointer
	);
NTSTATUS SafeCopyMemory(PVOID SrcAddr, PVOID DstAddr, ULONG Size);
ULONG GetOriginKiFastCallEntryAddress();
BOOL IsFromGameProcess();
NTSTATUS LookupProcessByName(
	IN PCHAR pcProcessName,
	OUT PEPROCESS *pEprocess
	);
NTSTATUS avQueryProcessFullPath(IN PEPROCESS pProcess,
	OUT PUNICODE_STRING pUniProcessPath);
VOID avGetDeviceNameFromNtPath(PUNICODE_STRING pUniNtPath,OUT PUNICODE_STRING pUniDeviceName);
NTSTATUS
	avRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING DeviceName,
	OUT PUNICODE_STRING DosName
	);
VOID avGetDosDirFromDosFullPath(PUNICODE_STRING pDosFullPath);
//
VOID Sleep(LONG MSeconds);
BOOL ValidateUnicodeString(PUNICODE_STRING usStr);
NTSTATUS GetPspCidTable(PHANDLE_TABLE *pPspHandleAddr);
