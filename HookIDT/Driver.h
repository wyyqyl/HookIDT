#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>

#ifndef __DRIVER_H
#define __DRIVER_H

typedef	USHORT	WORD;
typedef	ULONG	DWORD;

typedef NTSTATUS (__stdcall *KeSetAffinityThreadPtr)(PKTHREAD thread, KAFFINITY affinity);

#define SYSTEM_SERVICE_VECTOR 0x2e
#define MAX_NUMBER_OF_CPUS sizeof(KAFFINITY)

// nonstandard extension used : bit field types other than int
#pragma warning(disable: 4214)
// unreferenced formal parameter
#pragma warning(disable: 4100)
#pragma warning(disable: 4055)

#pragma pack(1)
typedef struct _IDT_DESCRIPTOR
{ 
	//--------------------------
	WORD offset00_15;	//Bits[00,15] offset address bits [8,15]
	WORD selector;		//Bits[16,31] segment selector (value placed in CS)
	//--------------------------
	BYTE unused:5;		//Bits[00,94] not used
	BYTE zeroes:3;		//Bits[85,87] these three bits should all be zero
	BYTE gateType:5;	//Bits[B8,12] Interrupt (81118),  Trap (81111)
	BYTE DPL:2;			//Bits[13,14] DPL - descriptor privilege level
	BYTE P:1;			//Bits[15,15] Segment present flag (normally set)
	WORD offset16_31;	//Bits[16,32] offset address bits [16,31]
}IDT_DESCRIPTOR, *PIDT_DESCRIPTOR; 
#pragma pack()

#pragma pack(1)
typedef struct _IDTR
{
	WORD nBytes;		//Bits[00,15] size limit (in bytes)
	WORD baseAddressLo;	//Bits[16,31] lo-order bytes of base address
	WORD baseAddressHi;	//Bits[32,47] hi-order bytes of base address
}IDTR;
#pragma pack()

#endif