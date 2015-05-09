#pragma once
#include "struct.h"
#include "UtilityFunc.h"
#include "InlineHook.h"
#include "Ntos.h"
#include "OwnProcess.h"
#define  MAX_REFER_CNT   50
//////////////////////////////////////////////////////////////////////////
typedef NTSTATUS (__stdcall *PFN_NTOPENPROCESS) (
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);

typedef NTSTATUS (__stdcall *NTREADVIRTUALMEMORY)(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
	);

typedef NTSTATUS (__stdcall *NTWRITEVIRTUALMEMORY) (
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in_bcount(BufferSize) CONST VOID *Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesWritten
	);
typedef NTSTATUS (__stdcall *NTCREATETHREAD)(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ProcessHandle,
	__out PCLIENT_ID ClientId,
	__in PCONTEXT ThreadContext,
	__in PVOID InitialTeb,
	__in BOOL CreateSuspended
	);

typedef NTSTATUS (__stdcall *PFN_NTCREATEPROCESS)(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ParentProcess,
	__in BOOLEAN InheritObjectTable,
	__in_opt HANDLE SectionHandle,
	__in_opt HANDLE DebugPort,
	__in_opt HANDLE ExceptionPort
	);
//
typedef NTSTATUS (_stdcall *PFN_NTCREATEPROCESSEX)(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ParentProcess,
	__in ULONG Flags,
	__in_opt HANDLE SectionHandle,
	__in_opt HANDLE DebugPort,
	__in_opt HANDLE ExceptionPort,
	__in ULONG JobMemberLevel
	);

typedef NTSTATUS (__stdcall *NTSUSPENDPROCESS)(
	__in HANDLE ProcessHandle
	);


typedef NTSTATUS (__stdcall *NTSUSPENDTHREAD)(
	__in HANDLE ThreadHandle,
	__out_opt PULONG PreviousSuspendCount
	);

//
typedef NTSTATUS (__stdcall *PFN_NTLOADDRIVER)(
	__in PUNICODE_STRING DriverServiceName
	);
//
typedef NTSTATUS (__stdcall *PFN_NTSETSYSTEMINFORMATION)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__in_bcount_opt(SystemInformationLength) PVOID SystemInformation,
	__in ULONG SystemInformationLength
	);
//
typedef NTSTATUS (__stdcall *PFN_NTCREATEFILE) (
	__out PHANDLE FileHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt PLARGE_INTEGER AllocationSize,
	__in ULONG FileAttributes,
	__in ULONG ShareAccess,
	__in ULONG CreateDisposition,
	__in ULONG CreateOptions,
	__in_bcount_opt(EaLength) PVOID EaBuffer,
	__in ULONG EaLength
	);
VOID HookKiFastCallEntryMiddle();
VOID UnhookKiFastCallEntryMiddle();

VOID WaitReferCntSubToZero();