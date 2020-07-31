// Winsock tutorial
// https://docs.microsoft.com/en-us/windows/win32/winsock/finished-server-and-client-code

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#include <time.h>
#include <stdio.h>

#include "Scanner.h"

// Can be negative
long long int baseAddress;
HANDLE handle;

void WriteMem(unsigned int psxAddr, void* pcAddr, int size)
{
	WriteProcessMemory(handle, (PBYTE*)(baseAddress + psxAddr), pcAddr, size, 0);
}

void ReadMem(unsigned int psxAddr, void* pcAddr, int size)
{
	ReadProcessMemory(handle, (PBYTE*)(baseAddress + psxAddr), pcAddr, size, 0);
}

void initialize()
{
	int choice = 0;
	HWND console = GetConsoleWindow();
	RECT r;
	GetWindowRect(console, &r); //stores the console's current dimensions

	// 300 + height of bar (35)
	MoveWindow(console, r.left, r.top, 640, 720, TRUE);

	// Initialize random number generator
	srand((unsigned int)time(NULL));

	printf("\n");
	printf("Step 1: Open any ps1 emulator\n");
	printf("Step 2: Open CTR SCUS_94426\n");
	printf("\n");
	printf("Step 3: Enter emulator PID from 'Details'\n");
	printf("           tab of Windows Task Manager\n");
	printf("Enter: ");

	DWORD procID = 0;
	scanf("%d", &procID);

	printf("\n");
	printf("Searching for CTR 94426 in emulator ram...\n");

	// open the process with procID, and store it in the 'handle'
	handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);

	// if handle fails to open
	if (!handle)
	{
		printf("Failed to open process\n");
		system("pause");
		exit(0);
	}

	// This idea to scan memory for 11 bytes to automatically
	// find that CTR is running, and to find the base address
	// of any emulator universally, was EuroAli's idea in the
	// CTR-Tools discord server. Thank you EuroAli

	// Shows at PSX address 0x8003C62C, only in CTR 94426
	unsigned char ctrData[12] = { 0x71, 0xDC, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0xD0, 0xF9, 0x00, 0x0C };

	// can't be nullptr by default or it crashes,
	// it will become 1 when the loop starts
	baseAddress = 0;

	// Modified from https://guidedhacking.com/threads/hyperscan-fast-vast-memory-scanner.9659/
	std::vector<UINT_PTR> AddressHolder = Hyperscan::HYPERSCAN_SCANNER::Scan(procID, ctrData, 12, Hyperscan::HyperscanAllignment4Bytes,
		Hyperscan::HyperscanTypeExact);

	// take the first (should be only) result
	baseAddress = AddressHolder[0];

	// Remove 0x8003C62C address of PSX memory,
	// to find the relative address where PSX memory
	// is located in RAM. It is ok for baseAddress
	// to be a negative number
	baseAddress -= 0x8003C62C;
}

struct
{
	unsigned int unk1;	// 0
	unsigned int unk2;	// 4
	unsigned int strPtr;// 8
	unsigned int unk3;	// c
	unsigned int unk4;	// 10
	unsigned int unk5;	// 14
	unsigned int unk6;	// 18
	unsigned int unk7;	// 1c
	unsigned int unk8;	// 20
	unsigned int unk9;	// 24
	unsigned int unkA;	// 28
	unsigned int funPtr;// 2C
	unsigned int bufPtr;// 30
} data;

bool OutOfRange(unsigned int addr)
{
	return addr < 0x80000000 || addr > 0x80200000;
}

bool InvalidStruct()
{
	// dont check function pointer
	// sometimes it is zero for nullptr

	return OutOfRange(data.strPtr)
		||  OutOfRange(data.bufPtr);
}

int main(int argc, char** argv)
{
	initialize();

	clock_t start = clock();
	clock_t end = clock();

	// Main loop...
	while (true)
	{
		// end of previous cycle
		end = clock();

		// If you finished in less than 1000ms (1 second) 
		int ms = end - start;
		if (ms < 1000) Sleep(1000 - ms);

		// start of next cycle
		start = clock();

		system("cls");

		int PtrFirstLink;
		ReadMem(0x80096b20+0x18d0, &PtrFirstLink, sizeof(PtrFirstLink));

		int currPtr = PtrFirstLink;

		// go forward till the end, then go backwards
		while (true)
		{
			// Get 0x48 node in linked-list
			ReadMem(currPtr, &data, sizeof(data));

			// If the structure is invalid, we reach the end			
			if (InvalidStruct())
			{
				// go back one
				currPtr -= 0x48;

				// exit loop
				break;
			}

			// If this structure is valid
			else
			{

				// go to next member
				currPtr += 0x48;
			}
		}

		// Now read and print them all,
		// this time going backwards
		while(true)
		{
			// Get 0x48 node in linked-list
			ReadMem(currPtr, &data, sizeof(data));

			// We need to check if the struct is valid,
			// because we will go back farther than PtrFirstLink,
			// which isn't really the first 0x48 structure. This
			// is the only way we currently know how to get all 
			// 0x48 structs

			if (InvalidStruct())
				break;

			// Use the pointer at offset 8 to get the string
			char stringData[16];
			ReadMem(data.strPtr, stringData, sizeof(stringData));

			// print data
			printf("Curr: %08X, FuncPtr: %08X, Buffer: %08X, String: %s\n",
				currPtr, data.funPtr, data.bufPtr, stringData);

			// go to next index in array
			currPtr -= 0x48;
		}
	}

	return 0;
}