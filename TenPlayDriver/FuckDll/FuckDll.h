// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� FUCKDLL_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// FUCKDLL_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
/*#define  FUCKDLL_EXPORTS*/
#ifdef FUCKDLL_EXPORTS
#define FUCKDLL_API __declspec(dllexport)
#else
#define FUCKDLL_API __declspec(dllimport)
#endif

// �����Ǵ� FuckDll.dll ������
class FUCKDLL_API CFuckDll {
public:
	CFuckDll(void);
	// TODO: �ڴ�������ķ�����
};

extern FUCKDLL_API int nFuckDll;

FUCKDLL_API int fnFuckDll(void);
extern "C" FUCKDLL_API void UnloadFuck(void);

extern "C" FUCKDLL_API void SetFuck(void);
