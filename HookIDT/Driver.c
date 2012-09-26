#include "Driver.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD HookIDTEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD HookIDTEvtDriverUnload;

PIDT_DESCRIPTOR idt2eAddr[MAX_NUMBER_OF_CPUS];
DWORD originalIDT2eISR;

void logSystemCall(DWORD dispatchID, DWORD stackPtr)
{
	KdPrint(("[RegisterSystemCall]: on CPU[%u] of %u, (%s, pid=%u, dispatchID=0x%x)\n",
		KeGetCurrentProcessorNumber() + 1, KeNumberProcessors, (BYTE *)PsGetCurrentProcess() + 0x16C, PsGetCurrentProcessId(), dispatchID));
}

__declspec(naked) void KiSystemServiceHook()
{
	__asm
	{
		// Before calling kernel functions,
		// fs should be set to 0x30
		pushad;
		pushfd;
		push fs;
		mov bx, 0x30;
		mov fs, bx;
				
		push edx;
		push eax;
		call logSystemCall;

		pop fs;
		popfd;
		popad;

		jmp originalIDT2eISR;
	}
}

DWORD makeDWORD(WORD hi, WORD lo)
{
	DWORD value = 0;
	value = value | (DWORD)hi;
	value <<= 16;
	value = value | (DWORD)lo;
	return value;
}

void HookCPU(DWORD dwProcAddress)
{
	DWORD dwIndex;
	PKTHREAD pkThread;
	KAFFINITY cpuBitMap;
	UNICODE_STRING usKeSetAffinityThread;
	KeSetAffinityThreadPtr KeSetAffinityThread;

	KdPrint(("[HookCPU]\n"));

	pkThread = KeGetCurrentThread();
	cpuBitMap = KeQueryActiveProcessors();
	RtlInitUnicodeString(&usKeSetAffinityThread, L"KeSetAffinityThread");
	KeSetAffinityThread = (KeSetAffinityThreadPtr)MmGetSystemRoutineAddress(&usKeSetAffinityThread);

	for (dwIndex = 0; dwIndex < MAX_NUMBER_OF_CPUS; ++dwIndex)
	{
		KAFFINITY currentCPU = cpuBitMap & (1 << dwIndex);
		if (currentCPU != 0)
		{
			IDTR idtr;
			PIDT_DESCRIPTOR idt;
			DWORD idt2e;

			KeSetAffinityThread(pkThread, currentCPU);

			if (idt2eAddr[dwIndex] == 0)
			{
				__asm sidt idtr
				idt = (PIDT_DESCRIPTOR)makeDWORD(idtr.baseAddressHi, idtr.baseAddressLo);
				idt2eAddr[dwIndex] = idt + SYSTEM_SERVICE_VECTOR;
				if (originalIDT2eISR == 0)
					originalIDT2eISR = makeDWORD(idt2eAddr[dwIndex]->offset16_31, idt2eAddr[dwIndex]->offset00_15);
				KdPrint(("IDT: 0x%08X, originalIDT2eISR: 0x%08X\n", (DWORD)idt, originalIDT2eISR));
			}
			idt2e = (DWORD)idt2eAddr[dwIndex];

			__asm
			{
				cli;
				mov eax, dwProcAddress;
				mov ebx, idt2e;

				mov [ebx], ax;
				shr eax, 16;
				mov [ebx+6], ax;
				sti;
			}
			KdPrint(("Processor[%d] is hooked, dwProcAddress: 0x%08X\n", dwIndex + 1, dwProcAddress));
		}
	}
	KeSetAffinityThread(pkThread, cpuBitMap);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

void HookInt2E(DWORD dwProcAddress)
{
	HANDLE hThread;
	CLIENT_ID cid;
	PVOID pThread;

	KdPrint(("Start hooking...\n"));

	PsCreateSystemThread(&hThread, 0L, NULL, NULL, &cid, (PKSTART_ROUTINE)HookCPU, (PVOID)dwProcAddress);
	if (hThread)
	{
		PsLookupThreadByThreadId(cid.UniqueThread, (PETHREAD *)&pThread);
		KeWaitForSingleObject(pThread, Executive, KernelMode, FALSE, NULL);
		ZwClose(hThread);
		KdPrint(("Hook is done.\n"));
	}
}

void HookIDTEvtDriverUnload(WDFDRIVER Driver)
{
	HookInt2E(originalIDT2eISR);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDF_DRIVER_CONFIG config = {0};

	KdPrint(("[DriverEntry]\n"));
	WDF_DRIVER_CONFIG_INIT(&config, HookIDTEvtDeviceAdd);
	config.EvtDriverUnload = HookIDTEvtDriverUnload;
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

	HookInt2E((DWORD)KiSystemServiceHook);

	return status;
}

NTSTATUS HookIDTEvtDeviceAdd(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDFDEVICE hDevice;

	KdPrint(("[HookIDTEvtDeviceAdd]\n"));
	status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice);
	return status;
}