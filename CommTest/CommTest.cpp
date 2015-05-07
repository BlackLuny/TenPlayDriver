// CommTest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include "Communication.h"

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

VOID SendCtrlCode(ULONG dwCode,LPVOID lpBuffer,DWORD dwBytesToRead)
{
	DWORD dwReadRet = 0;
	ReadFile((HANDLE)dwCode,
		lpBuffer,
		dwBytesToRead,
		&dwReadRet,
		NULL);

}
//从路径中获取上一级目录的名字

VOID GetLastDirNameFromPath(PUNICODE_STRING pUniPath,wchar_t *pLastDir)
{
	USHORT wLen = pUniPath->Length;
	USHORT wMaxLen = pUniPath->MaximumLength;
	wchar_t *p1,*p2;
	p1 = p2 = pUniPath->Buffer + wLen/sizeof(wchar_t) -1;
	while(*p1 != L'\\')
	{
		p1--;
	}
	memcpy(pLastDir,p1+1,(p2 - p1)*sizeof(wchar_t));

}
int _tmain(int argc, _TCHAR* argv[])
{
	//UNICODE_STRING uTestString = {0};
	//wchar_t szBuffer[] = L"E:\\DriverProject\\DriverProj\\TenPlayDriver\\TenPlayDriver\\debug\\i386"; 
	//wchar_t szTest[260]={0};
	////getchar();
	////char pch[20];
	SendCtrlCode(CTRL_PRINT_TEST,NULL,20);
	SendCtrlCode(CTRL_START_PROTECT,NULL,20);

	Sleep(1000 * 60 * 2);
	SendCtrlCode(CTRL_STOP_PROTECT,NULL,20);
	//uTestString.Length = wcslen(szBuffer) * sizeof(wchar_t);
	//uTestString.MaximumLength = uTestString.Length + sizeof(wchar_t);
	//uTestString.Buffer = szBuffer;
	//GetLastDirNameFromPath(&uTestString,szTest);
	//printf_s("last dir : %ws\n",szTest);
	//HANDLE h = INVALID_HANDLE_VALUE;
	//h = CreateFileA("D:\\test",GENERIC_READ,FILE_SHARE_READ,
	//	NULL,
	//	OPEN_EXISTING,
	//	FILE_ATTRIBUTE_NORMAL,
	//	NULL);
	//if(h == INVALID_HANDLE_VALUE)
	//{
	//	printf_s("error code : %x\n",GetLastError());
	//}
	//else
	//{
	//	printf_s("open success");
	//	CloseHandle(h);
	//}
	//getchar();
	return 0;
}

