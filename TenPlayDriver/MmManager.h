#pragma once
#include "struct.h"

PVOID mmAllocateBuffer(BOOL bPagedPool,SIZE_T NumberOfBytes);

VOID mmFreeBuffer(PVOID  *pBuffer);