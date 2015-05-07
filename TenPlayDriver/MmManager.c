#include "MmManager.h"

//��װһ�������ڴ溯��
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
//�ͷ��ڴ棬ͬʱ�����ָ����Ϊnull
VOID mmFreeBuffer(PVOID  *pBuffer)
{
	if (*pBuffer != NULL)
	{
		ExFreePool(*pBuffer);
		*pBuffer = NULL;
	}
}