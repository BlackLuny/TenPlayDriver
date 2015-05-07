#ifndef _KERNELRELOAD_H_
#define _KERNELRELOAD_H_
#include "struct.h"
#include "UtilityFunc.h"
#include "FileSystem.h"
#include "Fixrelocation.h"
#pragma pack(push,1)
typedef struct _KERNEL_MODULE_INFO{
	PVOID pOriginKernelBase;
	ULONG dwKernelSize;
	/*重载成功后的基址*/
	PVOID pReloadKernelBase;
	WCHAR wszKernelFullPath[260];
}KERNEL_MODULE_INFO,*PKERNEL_MODULE_INFO;
#pragma  pack(pop)

PVOID GetKernelModuleBase(PDRIVER_OBJECT DriverObject,CHAR *KernelModuleName);
BOOL PeReload(KERNEL_MODULE_INFO *pKmi,PDRIVER_OBJECT DeviceObject);
#endif
