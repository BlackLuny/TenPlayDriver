// FuckDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "FuckDll.h"
#include "stdio.h"

// ���ǵ���������һ��ʾ��
FUCKDLL_API int nFuckDll=0;

// ���ǵ���������һ��ʾ����
FUCKDLL_API int fnFuckDll(void)
{
	return 42;
}

// �����ѵ�����Ĺ��캯����
// �й��ඨ�����Ϣ������� FuckDll.h
CFuckDll::CFuckDll()
{
	return;
}

void trace0(char *fmt, ...)
{
	char out[1024];
	va_list body;
	va_start(body, fmt);
	vsprintf(out, fmt, body); // ��ע����ʽ��������ַ��� fmtt
	va_end(body);               //       ������ַ��� ou
	OutputDebugStringA(out); // ��ע�������ʽ������ַ�����������
}

VOID RemoveTheFlags(KBDLLHOOKSTRUCT * pKbdHook)
{
	pKbdHook->flags &= ~0x00000002;//LLKHF_LOWER_IL_INJECTED
	pKbdHook->flags &= ~0x00000010;//LLKHF_INJECTED
	//pKbdHook->flags &= ~0x00000001;
	//trace0("after handle pKbdHook->flags : 0x%x\n",pKbdHook->flags);
	//OutputDebugStringA("after handle pKbdHook->flags : 0x%8x\n",pKbdHook->flags);
}

LRESULT CALLBACK LowLevelKeyboardProc(
	_In_  int nCode,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	KBDLLHOOKSTRUCT * pKbdHook = NULL;
	if (nCode == HC_ACTION)
	{
		if (wParam == WM_KEYDOWN || wParam == WM_KEYUP)
		{
			pKbdHook = (KBDLLHOOKSTRUCT *)lParam;
			//ȥ������־
			//OutputDebugStringA("before handle pKbdHook->flags : 0x%8x\n",pKbdHook->flags);
			//trace0("before handle pKbdHook->flags : 0x%x\n",pKbdHook->flags);
			RemoveTheFlags(pKbdHook);
		}
	}
	return CallNextHookEx(NULL,nCode,wParam,lParam);
}
HHOOK g_idHook = NULL;

extern "C" FUCKDLL_API void UnloadFuck(void)
{
	if (g_idHook != NULL)
	{
		UnhookWindowsHookEx(g_idHook);
	}

}

extern "C" FUCKDLL_API  void SetFuck(void)
{
	//HHOOK WINAPI SetWindowsHookEx(
	//	_In_  int idHook,
	//	_In_  HOOKPROC lpfn,
	//	_In_  HINSTANCE hMod,
	//	_In_  DWORD dwThreadId
	//	);
	g_idHook = SetWindowsHookEx(WH_KEYBOARD_LL,
		LowLevelKeyboardProc,
		GetModuleHandle(L"FuckDll.dll"),
		0);
}
