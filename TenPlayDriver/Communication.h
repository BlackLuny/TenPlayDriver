#pragma once
#include "struct.h"
#include "UtilityFunc.h"
#include "InlineHook.h"
#include "OwnProcess.h"
#include "HookPort.h"
#include "NotifyRoutine.h"
#include "AntiSealup.h"
#include "FSDHook.h"
#include "GameInfo.h"
#include "NotifyRoutine.h"
//定义控制码

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
	)
#define  CTRL_BASE 0xa00
#define CTRL_EXPRESSION(i)   CTL_CODE(FILE_DEVICE_UNKNOWN,(CTRL_BASE+i),METHOD_BUFFERED,FILE_ANY_ACCESS)
//判断是不是控制码
#define CTRL_SUCCESS(code) (((code) &  0x88880000) == 0x88880000)


#define CTRL_PRINT_TEST	 CTRL_EXPRESSION(0)
#define CTRL_START_PROTECT	 CTRL_EXPRESSION(1)
#define CTRL_STOP_PROTECT	 CTRL_EXPRESSION(2)
#define CTRL_REMOVE_NOTIFY	 CTRL_EXPRESSION(3)

//#define  COMM_PRINT_TEST		COMM_CONTROL_CODE(0)
typedef NTSTATUS 
	(__stdcall *PFN_NTREADFILE)(
	__in HANDLE FileHandle,
	__in_opt HANDLE Event,
	__in_opt PIO_APC_ROUTINE ApcRoutine,
	__in_opt PVOID ApcContext,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__out_bcount(Length) PVOID Buffer,
	__in ULONG Length,
	__in_opt PLARGE_INTEGER ByteOffset,
	__in_opt PULONG Key
	);
//
//BOOL InitCommunication();
//VOID DeleteCommunication();
NTSTATUS IoDispatch(PDEVICE_OBJECT pDeviceObject,PIRP pIrp);
NTSTATUS IoHelloDDKDispatch(PDEVICE_OBJECT pDeviceObject,PIRP pIrp);
NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject);
VOID DeleteDevice(PDEVICE_OBJECT DeviceObject);