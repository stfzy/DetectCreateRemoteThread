// TestDetectCMT.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
class aaa
{
public:
	aaa() {}
};
int main()
{
	float * f;
	ULONGLONG i;
	 
	i = static_cast<ULONG >(f);
	i = reinterpret_cast<ULONGLONG>(f);


    return 0;
}

