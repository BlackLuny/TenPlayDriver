
// MsgTestDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "MsgTest.h"
#include "MsgTestDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#pragma comment(lib,"..\\debug\\FuckDll.lib")
#include "..\\FuckDll\\FuckDll.h"
// CMsgTestDlg 对话框




CMsgTestDlg::CMsgTestDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CMsgTestDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMsgTestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMsgTestDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMsgTestDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMsgTestDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CMsgTestDlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CMsgTestDlg 消息处理程序

BOOL CMsgTestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMsgTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMsgTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMsgTestDlg::OnBnClickedButton1()
{
	SetFuck();
}


void CMsgTestDlg::OnBnClickedButton2()
{
	UnloadFuck();
}


void CMsgTestDlg::OnBnClickedButton3()
{
	
	// Simulate a key press
	keybd_event( 0x41,
		MapVirtualKey(0x41,0),
		KEYEVENTF_EXTENDEDKEY | 0,
		0 );

	// Simulate a key release
	keybd_event( 0x41,
		MapVirtualKey(0x41,0),
		KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP,
		0);
}
