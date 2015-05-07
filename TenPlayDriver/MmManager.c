#include "MmManager.h"

//包装一下申请内存函数
PVOID mmAllocateBuffer(BOOL bPagedPool,SIZE_T NumberOfBytes)
{
	PVOID pBuffer = NULL;
	POOL_TYPE enumPoolType = bPagedPool ? PagedPool:NonPagedPool;
	pBuffer = ExAllocatePoolWithTag(enumPoolType,NumberOfBytes,'link');
	if (!pBuffer)
	{
		return NULL;
	}
	else
	{
		RtlZeroMemory(pBuffer,NumberOfBytes);
		return pBuffer;
	}
}
//释放内存，同时负责把指针置为null
VOID mmFreeBuffer(PVOID  *pBuffer)
{
	if (*pBuffer != NULL)
	{
		ExFreePool(*pBuffer);
		*pBuffer = NULL;
	}
}