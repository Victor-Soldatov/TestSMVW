#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <iomanip>
#include <string>
#pragma hdrstop
#pragma comment(lib, "Psapi.lib ")
using namespace std;

#define PADDING						2
#define ADDRESS_WIDTH				8
#define SIZE_WIDTH					8
#define PROTECT_WIDTH				20
#define STATE_WIDTH					13
#define TYPE_WIDTH					13
#define CONSOLE_WIDTH				IMAGE_SIZEOF_SHORT_NAME + ADDRESS_WIDTH + SIZE_WIDTH + ADDRESS_WIDTH + ADDRESS_WIDTH + PROTECT_WIDTH + SIZE_WIDTH + PROTECT_WIDTH + STATE_WIDTH + TYPE_WIDTH + 9 * PADDING

#define PROCESSES_LIST_INIT_CAP		16

const __wchar_t pwszDoneMessage[] = L"Application is done.";

void DecodeMemoryProtectionValue(__in DWORD dwProtect)
{
	if ((dwProtect & PAGE_EXECUTE) != 0)
		wcout << L"[EXECUTE]";
	if ((dwProtect & PAGE_EXECUTE_READ) != 0)
		wcout << L"[EXECUTE_READ]";
	if ((dwProtect & PAGE_EXECUTE_READWRITE) != 0)
		wcout << L"[EXECUTE_READWRITE]";
	if ((dwProtect & PAGE_EXECUTE_WRITECOPY) != 0)
		wcout << L"[EXECUTE_WRITECOPY]";
	if ((dwProtect & PAGE_NOACCESS) != 0)
		wcout << L"[NOACCESS]";
	if ((dwProtect & PAGE_READONLY) != 0)
		wcout << L"[READONLY]";
	if ((dwProtect & PAGE_READWRITE) != 0)
		wcout << L"[READWRITE]";
	if ((dwProtect & PAGE_WRITECOPY) != 0)
		wcout << L"[WRITECOPY]";
	if ((dwProtect & PAGE_GUARD) != 0)
		wcout << L"[GUARD]";
	if ((dwProtect & PAGE_NOCACHE) != 0)
		wcout << L"[NOCACHE]";
	if ((dwProtect & PAGE_WRITECOMBINE) != 0)
		wcout << L"[WRITECOMBINE]";
}

void DecodeStateValue(__in DWORD dwState)
{
	if ((dwState & MEM_COMMIT) != 0)
		wcout << L"[MEM_COMMIT]";
	if ((dwState & MEM_FREE) != 0)
		wcout << L"[MEM_FREE]";
	if ((dwState & MEM_RESERVE) != 0)
		wcout << L"[MEM_RESERVE]";
}

void DecodeTypeValue(__in DWORD dwType)
{
	if ((dwType & MEM_IMAGE) != 0)
		wcout << L"[MEM_IMAGE]";
	if ((dwType & MEM_MAPPED) != 0)
		wcout << L"[MEM_MAPPED]";
	if ((dwType & MEM_PRIVATE) != 0)
		wcout << L"[MEM_PRIVATE]";
}

__inline SHORT GetSmallRectWidth(__in SMALL_RECT& smRect)
{
	return smRect.Right - smRect.Left;
}

int __cdecl wmain(int argc, __wchar_t* argv[])
{
	HANDLE hStdOut(::GetStdHandle(STD_OUTPUT_HANDLE));
	CONSOLE_CURSOR_INFO cci = { 0 };
	BOOL fbCursorAdjusted(FALSE);

	if (INVALID_HANDLE_VALUE != hStdOut)
	{
		if (::GetConsoleCursorInfo(hStdOut, &cci))
		{
			CONSOLE_CURSOR_INFO cciTmp = cci;
			cciTmp.bVisible = FALSE;
			fbCursorAdjusted = ::SetConsoleCursorInfo(hStdOut, &cciTmp);
		}

		COORD MaxSize = ::GetLargestConsoleWindowSize(hStdOut);
		if (MaxSize.X > CONSOLE_WIDTH)
		{
			CONSOLE_SCREEN_BUFFER_INFO csbi = { 0 };
			if (::GetConsoleScreenBufferInfo(hStdOut, &csbi) && GetSmallRectWidth(csbi.srWindow) <= CONSOLE_WIDTH)
			{
				COORD NewConsoleBufferSize = { 0 };
				NewConsoleBufferSize.X = CONSOLE_WIDTH + 1;
				NewConsoleBufferSize.Y = MaxSize.Y;

				if (::SetConsoleScreenBufferSize(hStdOut, NewConsoleBufferSize))
				{
					SMALL_RECT smrConsole = csbi.srWindow;
					smrConsole.Right = csbi.srWindow.Left + CONSOLE_WIDTH;
					::SetConsoleWindowInfo(hStdOut, TRUE, &smrConsole);
				}
			}
		}
	}

	wcout << L"Test PE32 console utilities app." << endl;

	MODULEINFO mi = { 0 };

	if (::GetModuleInformation(::GetCurrentProcess(), ::GetModuleHandleW(nullptr), &mi, sizeof(MODULEINFO)))
	{
		wcout << L"Module information is obtained." << endl;
		wcout << L"Base of image: " << hex << mi.lpBaseOfDll << L"h." << endl;
		wcout << L"Enumerating sections ..." << endl << endl;

		PIMAGE_DOS_HEADER lpImgDOSHdr(reinterpret_cast<PIMAGE_DOS_HEADER>(mi.lpBaseOfDll));
		PIMAGE_NT_HEADERS lpImgNTHdrs(reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<UINT_PTR>(lpImgDOSHdr) + lpImgDOSHdr ->e_lfanew));
		PIMAGE_FILE_HEADER lpImgFileHdr(&lpImgNTHdrs ->FileHeader);
		PIMAGE_SECTION_HEADER lpImgSectionHdr(IMAGE_FIRST_SECTION(lpImgNTHdrs));

		wcout << resetiosflags(ios::adjustfield) << setiosflags(ios::right) << setw(IMAGE_SIZEOF_SHORT_NAME + PADDING) << L"Section";
		wcout << setw(ADDRESS_WIDTH + PADDING) << L"Address";
		wcout << setw(SIZE_WIDTH + PADDING) << L"Size";
		wcout << setw(ADDRESS_WIDTH + PADDING) << L"Alloc at";
		wcout << setw(ADDRESS_WIDTH + PADDING) << L"Base";
		wcout << setw(PROTECT_WIDTH + PADDING) << L"Alloc. protect";
		wcout << setw(SIZE_WIDTH + PADDING) << L"Region";
		wcout << setw(PROTECT_WIDTH + PADDING) << L"Protect";
		wcout << setw(STATE_WIDTH + PADDING) << L"State";
		wcout << setw(TYPE_WIDTH) << L"Type";
		wcout << endl;
		wcout << endl;

		for (WORD nIndex(0); nIndex < lpImgFileHdr ->NumberOfSections; ++nIndex)
		{
			LPVOID lpSectionStart(reinterpret_cast<LPVOID>(lpImgSectionHdr[nIndex].VirtualAddress + reinterpret_cast<DWORD>(mi.lpBaseOfDll)));
			string strSectionName(IMAGE_SIZEOF_SHORT_NAME + 1, '\0');
			for (int i(0); i < IMAGE_SIZEOF_SHORT_NAME; ++i)
				if (lpImgSectionHdr[nIndex].Name[i])
					strSectionName[i] = static_cast<char>(lpImgSectionHdr[nIndex].Name[i]);
				else
					strSectionName[i] = ' ';

			cout << resetiosflags(ios::adjustfield) << setiosflags(ios::right) << setw(IMAGE_SIZEOF_SHORT_NAME + PADDING) << strSectionName;
			wcout << resetiosflags(ios::adjustfield) << setiosflags(ios::right) << setw(ADDRESS_WIDTH + PADDING) << hex << lpSectionStart;
			wcout << setw(SIZE_WIDTH + PADDING) << dec << lpImgSectionHdr[nIndex].Misc.VirtualSize;

			MEMORY_BASIC_INFORMATION mbi;
			if (sizeof(MEMORY_BASIC_INFORMATION) != ::VirtualQuery(lpSectionStart, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
			{
				DWORD dwErrorCode(::GetLastError());
				wcout << resetiosflags(ios::adjustfield);
				wcout << endl;
				wcout << endl;
				wcout << L"VirtualQuery is failed with code " << hex << dwErrorCode << L"h (" << dec << dwErrorCode << L"d)." << endl;
				::getchar();
				return -1;
			}
			else
			{
				wcout << setw(ADDRESS_WIDTH + PADDING) << hex << mbi.BaseAddress;
				wcout << setw(ADDRESS_WIDTH + PADDING) << hex << mbi.AllocationBase;
				wcout << resetiosflags(ios::adjustfield) << setiosflags(ios::internal) << setw(PROTECT_WIDTH + PADDING);
				DecodeMemoryProtectionValue(mbi.AllocationProtect);
				wcout << resetiosflags(ios::adjustfield) << setiosflags(ios::right) << setw(SIZE_WIDTH + PADDING) << dec << mbi.RegionSize;
				wcout << resetiosflags(ios::adjustfield) << setiosflags(ios::internal) << setw(PROTECT_WIDTH + PADDING);
				DecodeMemoryProtectionValue(mbi.Protect);
				wcout << resetiosflags(ios::adjustfield) << setiosflags(ios::internal) << setw(STATE_WIDTH + PADDING);
				DecodeStateValue(mbi.State);
				wcout << setw(TYPE_WIDTH);
				DecodeTypeValue(mbi.Type);
				wcout << endl;
			}
		}		
	}
	else
	{
		DWORD dwErrorCode(::GetLastError());
		wcout << resetiosflags(ios::adjustfield);
		wcout << endl;
		wcout << endl;
		wcout << L"GetModuleInformation is failed with code " << dec << dwErrorCode << L" (" << hex << dwErrorCode << L"h)." << endl;
		::getchar();
		return -2;
	}

	wcout << resetiosflags(ios::adjustfield);
	wcout << endl;
	wcout << endl;

	DWORD lpdwProcessListLen[PROCESSES_LIST_INIT_CAP] = { 0 };
	DWORD dwConAppTotal(::GetConsoleProcessList(lpdwProcessListLen, PROCESSES_LIST_INIT_CAP));

	if (dwConAppTotal < 2)
	{
		wcout << L"Application is about to shutdown. ";
		HANDLE hStdInput(::GetStdHandle(STD_INPUT_HANDLE));
		if (hStdInput)
		{
			wcout << L"Press any key to shutdown the application ..." << endl;
			::FlushConsoleInputBuffer(hStdInput);
			INPUT_RECORD ir = { 0 };
			do
			{
				DWORD dwEventsRead(0);
				if (!::ReadConsoleInputW(hStdInput, &ir, 1, &dwEventsRead))
					break;
			}
			while (ir.EventType != KEY_EVENT);
			::FlushConsoleInputBuffer(hStdInput);
		}
		else
			wcout << endl << pwszDoneMessage << endl;
	}
	else
		wcout << pwszDoneMessage << endl;

	if (fbCursorAdjusted)
		::SetConsoleCursorInfo(hStdOut, &cci);

	return 0;
	UNREFERENCED_PARAMETER(argv);
	UNREFERENCED_PARAMETER(argc);
}
