#include "Driver.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD HookIDTEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD HookIDTEvtDriverUnload;

KEVENT syncEvent;
volatile LONG nIDTHooked;
volatile LONG nIDTUnhooked;
LONG nProcessors;
PIDT_DESCRIPTOR idt2e;
DWORD oldIdt2ePtr;

void logSystemCall(DWORD dispatchID, DWORD stackPtr)
{
	KdPrint(("[RegisterSystemCall]: on CPU[%u] of %u, (%s, pid=%u, dispatchID=0x%x)\n",
		KeGetCurrentProcessorNumber(), KeNumberProcessors, (BYTE *)PsGetCurrentProcess() + 0x16C, PsGetCurrentProcessId(), dispatchID));
}

__declspec(naked) void KiSystemServiceHook()
{
	__asm
	{
		pushad;
		pushfd;
		push fs;
		mov bx, 0x30;
		mov fs, bx;
		push ds;
		push es;

		push edx;
		push eax;
		call logSystemCall;

		pop es;
		pop ds;
		pop fs;
		popfd;
		popad;

		jmp oldIdt2ePtr;
	}
}

void HookInt2E()
{
	DWORD dwISRAddress;

	KdPrint(("[HookInt2E]\n"));

	dwISRAddress = makeDWORD(idt2e->offset16_31, idt2e->offset00_15);
	if (dwISRAddress == (DWORD)KiSystemServiceHook)
	{
		KdPrint(("Processor[%d] is hooked already\n", KeGetCurrentProcessorNumber()));
		KeSetEvent(&syncEvent, 0, FALSE);
		PsTerminateSystemThread(0);
	}

	__asm
	{
		cli;
		lea eax, KiSystemServiceHook;
		mov ebx, idt2e;

		mov [ebx], ax;
		shr eax, 16;
		mov [ebx+6], ax;
		sti;
	}
	KdPrint(("Processor[%d] is hooked\n", KeGetCurrentProcessorNumber()));
	InterlockedIncrement(&nIDTHooked);
	KeSetEvent(&syncEvent, 0, FALSE);
	PsTerminateSystemThread(0);
}

void HookAllCPUs()
{
	PIDT_DESCRIPTOR idt;
	HANDLE hThread;
	IDTR idtr;

	KdPrint(("[HookAllCPUs]\n"));

	nProcessors = KeNumberProcessors;
	__asm
	{
		cli;
		sidt idtr;
		sti;
	}
	idt = (PIDT_DESCRIPTOR)makeDWORD(idtr.baseAddressHi, idtr.baseAddressLo);
	idt2e = &idt[SYSTEM_SERVICE_VECTOR];
	oldIdt2ePtr = makeDWORD(idt2e->offset16_31, idt2e->offset00_15);

	KdPrint(("IDT: 0x%08X, OldIDT2ePtr: 0x%08X\n", (DWORD)idt, oldIdt2ePtr));
	KdPrint(("Start hooking...\n"));

	nIDTHooked = 0;
	KeInitializeEvent(&syncEvent, SynchronizationEvent, FALSE);

	#pragma warning(disable: 4127)
	while (TRUE)
	{
		PsCreateSystemThread(&hThread, (ACCESS_MASK)0L, NULL, NULL, NULL, (PKSTART_ROUTINE)HookInt2E, NULL);
		KeWaitForSingleObject(&syncEvent, Executive, KernelMode, FALSE, NULL);
		if (nIDTHooked == nProcessors)
			break;
	}
	KdPrint(("Hook is done.\n"));
	KeSetEvent(&syncEvent, 0, FALSE);
}

void UnhookInt2E()
{
	DWORD dwISRAddress;

	KdPrint(("[UnhookInt2E]\n"));

	dwISRAddress = makeDWORD(idt2e->offset16_31, idt2e->offset00_15);
	if (dwISRAddress == oldIdt2ePtr)
	{
		KdPrint(("Processor[%d] is unhooked already\n", KeGetCurrentProcessorNumber()));
		KeSetEvent(&syncEvent, 0, FALSE);
		PsTerminateSystemThread(0);
	}

	__asm
	{
		cli;
		mov eax, oldIdt2ePtr;
		mov ebx, idt2e;

		mov [ebx], ax;
		shr eax, 16;
		mov [ebx+6], ax;
		sti;
	}
	KdPrint(("Processor[%d] is unhooked\n", KeGetCurrentProcessorNumber()));
	InterlockedIncrement(&nIDTUnhooked);
	KeSetEvent(&syncEvent, 0, FALSE);
	PsTerminateSystemThread(0);
}

void UnhookAllCPUs()
{
	HANDLE hThread;

	KdPrint(("[UnhookAllCPUs]\n"));

	KdPrint(("Start unhooking...\n"));

	nIDTUnhooked = 0;
	KeInitializeEvent(&syncEvent, SynchronizationEvent, FALSE);

	while (TRUE)
	{
		PsCreateSystemThread(&hThread, (ACCESS_MASK)0L, NULL, NULL, NULL, (PKSTART_ROUTINE)UnhookInt2E, NULL);
		KeWaitForSingleObject(&syncEvent, Executive, KernelMode, FALSE, NULL);
		if (nIDTUnhooked == nProcessors)
			break;
	}
	KdPrint(("Unhook is done.\n"));
	KeSetEvent(&syncEvent, 0, FALSE);
}

void HookIDTEvtDriverUnload(WDFDRIVER Driver)
{
	UnhookAllCPUs();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDF_DRIVER_CONFIG config = {0};

	KdPrint(("[DriverEntry]\n"));
	WDF_DRIVER_CONFIG_INIT(&config, HookIDTEvtDeviceAdd);
	config.EvtDriverUnload = HookIDTEvtDriverUnload;
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

	HookAllCPUs();

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