/***************************************************************************************
* AUTHOR : vLink
* DATE   : 2015-4-12
* MODULE : TenPlayDriver.C
* 
* Command: 
*	Source of IOCTRL Sample Driver
*
* Description:
*		Demonstrates communications between USER and KERNEL.
*
****************************************************************************************
* Copyright (C) 2010 vLink.
****************************************************************************************/
#include "main.h"
#include "UtilityFunc.h"
#include "Communication.h"
#include "WindowsVersion.h"
#include "Ntos.h"
#include "NotifyRoutine.h"
extern CHAR OwnProcessName[30];
extern LONG g_nHookPortRefCnt;

PDRIVER_OBJECT g_MyDriverObject = NULL;
/********************************************************************/
VOID
DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{	
	//移除通信
	DeleteDevice(pDriverObj->DeviceObject);
	FreeReloadNtosPool();
	return;
}

/********************************************************************/

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
	NTSTATUS status				= STATUS_UNSUCCESSFUL;
	PEPROCESS	OwnProcess		= NULL;
	pDriverObj->DriverUnload = DriverUnload;
	g_MyDriverObject = pDriverObj;

	//初始化windows版本
	GetWindowsVersion();
	/*初始化通信*/
	if (LookupProcessByName(OwnProcessName,&OwnProcess)!= STATUS_SUCCESS)
	{
		return STATUS_UNSUCCESSFUL;
		//不是我的进程加载的，失败！
	}
	status = CreateDevice(pDriverObj);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	pDriverObj->MajorFunction[IRP_MJ_CLOSE]          = IoDispatch;
	pDriverObj->MajorFunction[IRP_MJ_CREATE]         = IoDispatch;
	pDriverObj->MajorFunction[IRP_MJ_WRITE]          = IoDispatch;
	pDriverObj->MajorFunction[IRP_MJ_READ]           = IoDispatch;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoHelloDDKDispatch;
	avPrint("InitCommunication success...");

	if (InitOwnProcess() != STATUS_SUCCESS)
	{
		avPrint("InitProtectedProcess failed...");
		//移除通信
		DeleteDevice(pDriverObj->DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}

	avPrint("InitOwnProcess success...");
	if (!InitNotifyRoutineAddr())
	{
		avPrint("InitNotifyRoutineAddr failed...");
		//移除通信
		DeleteDevice(pDriverObj->DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}
	//设置删除线程
	// if (avSetDeleteThread() != STATUS_SUCCESS)
	// {
		// avPrint("avSetDeleteNotifyThread failed...");
		// DeleteCommunication();
		// return STATUS_UNSUCCESSFUL;
	// }
	if (ReloadNtos(pDriverObj) != STATUS_SUCCESS)
	{
		avPrint("ReloadNtos failed...");
		//移除通信
		DeleteDevice(pDriverObj->DeviceObject);
		//DeleteCommunication();
		return STATUS_UNSUCCESSFUL;
	}
	avPrint("ReloadNtos success...");
	return status;
}

