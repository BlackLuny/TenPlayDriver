#pragma once
//定义控制码
/*
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
	)*/
#define  CTRL_BASE 0x88880000
#define CTRL_EXPRESSION(i)   (CTRL_BASE + i)
//判断是不是控制码
#define CTRL_SUCCESS(code) (((code) &  0x88880000) == 0x88880000)


#define CTRL_PRINT_TEST	 CTRL_EXPRESSION(666)
#define CTRL_START_PROTECT	 CTRL_EXPRESSION(0)
#define CTRL_STOP_PROTECT	 CTRL_EXPRESSION(1)

//#define  COMM_PRINT_TEST		COMM_CONTROL_CODE(0)