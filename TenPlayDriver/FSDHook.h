#pragma once
#include "struct.h"
#include "InlineHook.h"
#include "Ntos.h"
#include "OwnProcess.h"

extern POBJECT_TYPE *IoDriverObjectType;
typedef NTSTATUS (__stdcall *PFN_NTCREATEFILE)(
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

typedef NTSTATUS (__stdcall *PFN_IOCREATEFILE)(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG Disposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength,
	IN CREATE_FILE_TYPE CreateFileType,
	IN PVOID ExtraCreateParameters OPTIONAL,
	IN ULONG Options
	);
//
typedef NTSTATUS (__stdcall *PFN_NTFSCREATEDISPATCH)(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
	);
//
//VOID HookNtfsDispatchCreate();
//VOID UnhookNtfsDispatchCreate();
VOID HookIoCreateFile();
VOID UnhookIoCreateFile();