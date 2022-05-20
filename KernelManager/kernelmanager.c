#include <ntstatus.h>

#include "Driver/Utils.h"
#include "Driver/Structs.h"

PVOID obHandle;
t_Win32FreePool Win32FreePool;
MmAllocateIndependentPages_t MmAllocateIndependentPages;

OB_PREOP_CALLBACK_STATUS MyCallback( PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OpInfo )
{
	HANDLE pid            =   0;
	char   szProcName[16] = { 0 };
	
	pid = PsGetProcessId( ( PEPROCESS )OpInfo->Object );
	strcpy( szProcName, get_process_name_by_id( pid ) );
	log( "Call Back create handle name = %s pId - %i\n", szProcName, pid );

	return OB_PREOP_SUCCESS;
}

void register_call_back() {
	OB_OPERATION_REGISTRATION OperationRegistration;
	OB_CALLBACK_REGISTRATION CallbackRegistration;
	RtlSecureZeroMemory( &OperationRegistration, sizeof( OB_OPERATION_REGISTRATION ) );
	RtlSecureZeroMemory( &CallbackRegistration, sizeof( OB_CALLBACK_REGISTRATION ) );

	UNICODE_STRING callbackAltitude;
	RtlInitUnicodeString( &callbackAltitude, L"1986" );

	OperationRegistration.ObjectType = PsProcessType;
	OperationRegistration.Operations |= OB_OPERATION_HANDLE_CREATE;
	OperationRegistration.Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	OperationRegistration.PreOperation = &MyCallback;
	OperationRegistration.PostOperation = NULL;

	CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	CallbackRegistration.Altitude = callbackAltitude;
	CallbackRegistration.OperationRegistrationCount = 1;
	CallbackRegistration.RegistrationContext = NULL;
	CallbackRegistration.OperationRegistration = &OperationRegistration;

	NTSTATUS status = ObRegisterCallbacks( &CallbackRegistration, &obHandle );
	if(!NT_SUCCESS( status )) {
		err( "Error ObRegisterCallbacks ! %lu \n", status );
	}
}

NTSTATUS ImageCallback( PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo ) {
	NTSTATUS status;
	PWCHAR parameter = NULL;
	ULONG currentProcessId;
	
	if ( ImageInfo ) {
		currentProcessId = ( ULONG )PsGetCurrentProcessId();

		if ( ImageInfo->SystemModeImage ) {
			parameter = ExAllocatePoolWithTag( NonPagedPool, (256 + 1) * sizeof( WCHAR ), 'tag' );
			if ( parameter && NT_SUCCESS( RtlStringCchPrintfW( parameter, 256, L"1,0,s,DriverName->%wZ", FullImageName ) ) ) {
				log( "Driver %s loaded - process id - %i \n", FullImageName->Buffer, ProcessId );
				ExFreePool( parameter );
				return;
			} else {
				log( "DriverName->undefined \n" );
				if ( parameter )
					ExFreePool( parameter );
				return;
			}
		}
	}
}

void DrvUnload( PDRIVER_OBJECT DriverObject ) {
	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING( L"\\DosDevices\\Aos" );
	IoDeleteSymbolicLink( &dosDeviceName );
	IoDeleteDevice( DriverObject->DeviceObject );

	log( "Was unload ! \n" );
}

NTSTATUS IoClose( PDEVICE_OBJECT DeviceObject, PIRP Irp ) {
	Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return STATUS_ACCESS_DENIED;
}

NTSTATUS IoCreate( PDEVICE_OBJECT DeviceObject, PIRP Irp ) {
	log( "IoCreate ! \n" );
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );

	return STATUS_SUCCESS;
}

NTSTATUS IoControl( PDEVICE_OBJECT DeviceObj, PIRP pIrp ) {
	PIO_STACK_LOCATION irp = IoGetCurrentIrpStackLocation( pIrp );

	switch ( irp->Parameters.DeviceIoControl.IoControlCode ) {
		case IOCTL_READ_MEMORY:
		{
			ULONG inputLength = irp->Parameters.DeviceIoControl.InputBufferLength;
			PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;

			PREAD_MEMORY readBuffer = ( PREAD_MEMORY )(buffer);
			size_t retSize = 0;

			read( readBuffer->pId, readBuffer->address, readBuffer->size, buffer, &retSize );

			pIrp->IoStatus.Information = retSize;
			pIrp->IoStatus.Status = STATUS_SUCCESS;

			IoCompleteRequest( pIrp, IO_NO_INCREMENT );

			return STATUS_SUCCESS;
		}
		case IOCTL_WRITE_MEMORY:
		{
			ULONG inputLength = irp->Parameters.DeviceIoControl.InputBufferLength;
			PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;

			PWRITE_MEMORY pWriteMemory = ( PWRITE_MEMORY )(buffer);
			
			write( pWriteMemory->pId, 
				pWriteMemory->wAddress, 
				pWriteMemory->srcAddress, 
				pWriteMemory->wSize );

			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_SUCCESS;

			IoCompleteRequest( pIrp, IO_NO_INCREMENT );

			return STATUS_SUCCESS;
		}
		case IOCTL_CHANGE_PROTECT:
		{
			ULONG inputLength = irp->Parameters.DeviceIoControl.InputBufferLength;
			PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;

			PCHANGE_PROTECT pChangeProtect = ( PCHANGE_PROTECT )(buffer);

			change_virtual_mem_protect( pChangeProtect->pId,
				pChangeProtect->address,
				pChangeProtect->size,
				pChangeProtect->newProtect,
				pChangeProtect->oldProtect );

			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_SUCCESS;

			IoCompleteRequest( pIrp, IO_NO_INCREMENT );

			return STATUS_SUCCESS;
		}
		case IOCTL_ALLOCATE_MEMORY:
		{
			NTSTATUS ntStatus = 0;
			KAPC_STATE apc = {0};
			PEPROCESS process;
			ULONG inputLength = irp->Parameters.DeviceIoControl.InputBufferLength;
			PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;

			PALLOCATE_MEMORY pAllocateMem = ( PALLOCATE_MEMORY )(buffer);
			__try {
				ntStatus = PsLookupProcessByProcessId( pAllocateMem->pId, &process );
				if ( !NT_SUCCESS( ntStatus ) ) {
					log( "Error: PsLookupProcessByProcessId in AllocateVmMem ! \n" );
					pIrp->IoStatus.Information = 0;
					pIrp->IoStatus.Status = ntStatus;

					IoCompleteRequest( pIrp, IO_NO_INCREMENT );
					return ntStatus;
				}

				KeStackAttachProcess( process, &apc );

				ntStatus = ZwAllocateVirtualMemory( ZwCurrentProcess(),
					pAllocateMem->allocateBase,
					0,
					pAllocateMem->size,
					pAllocateMem->allcoateType,
					pAllocateMem->protect );
				if ( !NT_SUCCESS( ntStatus ) ) {
					log( "Error: ZwAllocateVirtualMemory in AllocateVmMem ! \n" );

					pIrp->IoStatus.Information = 0;
					pIrp->IoStatus.Status = ntStatus;

					KeUnstackDetachProcess( &apc );

					IoCompleteRequest( pIrp, IO_NO_INCREMENT );
					return ntStatus;
				}
			}
			__except ( 1 ) {
				err( "Exception ! code %lu \n", GetExceptionCode() );
				KeUnstackDetachProcess( &apc );
				return;
			}
			KeUnstackDetachProcess( &apc );

			pIrp->IoStatus.Information = 0;
			pIrp->IoStatus.Status = STATUS_SUCCESS;

			IoCompleteRequest( pIrp, IO_NO_INCREMENT );

			return STATUS_SUCCESS;
		}
	}

}

__int64 __fastcall hook( __int64 a, __int64 b, __int64 c ) {
	log( "%p \n", a );

	return Win32FreePool( a, b, c );
}

NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath ) {

	NTSTATUS ntStatus         = 0;
	PDEVICE_OBJECT pDeviceObj = 0;

	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING( L"\\DosDevices\\Aos") ;
	UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Device\\Aos" );

	//BSOD 
	//ntStatus = PsSetLoadImageNotifyRoutine( ImageCallback );
	//if ( !NT_SUCCESS( ntStatus ) ) {
	//	err( "ntStatus = %i PsSetLoadImageNotifyRoutine Error ! \n", ntStatus );
	//	return ntStatus;
	//}

	//PEPROCESS out;
	//PsLookupProcessByProcessId( pid, &out );
r
	//KAPC_STATE state;
	//KeStackAttachProcess( out, &state );

	uintptr_t win32k_imagebase = get_pid_by_name( "win32kbase.sys" );

	uintptr_t ptr_win32freepool = win32k_imagebase + 0x5D60; // See win32kbase!NtUserSetSysColors. The ptr we swap is a global that
	Win32FreePool = *( t_Win32FreePool* )ptr_win32freepool;      // holds the address to Win32FreePool
	write_to_read_only_memory( *( t_Win32FreePool* )ptr_win32freepool, &hook, 8 );
	log( "Base = %p hook = %p \n", win32k_imagebase, ptr_win32freepool );

	//KeUnstackDetachProcess( &state );

	ntStatus = IoCreateDevice( DriverObject,
		0,
		&driverName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDeviceObj );

	log( "%i %i \n", dosDeviceName.Length, driverName.Length );

	if ( !NT_SUCCESS( ntStatus ) ) {
		err( "ntStatus = %i IoCreateDevice Error ! \n", ntStatus );
		return ntStatus;
	}

	SetFlag( pDeviceObj->Flags, DO_BUFFERED_IO );

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IoCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IoClose;

	DriverObject->DriverUnload = DrvUnload;

	ntStatus = IoCreateSymbolicLink( &dosDeviceName, &driverName );
	if ( !NT_SUCCESS( ntStatus ) ) {
		err( "ntStatus = %i IoCreateSymbolicLink Error ! \n", ntStatus );
		return ntStatus;
	}
	log( "DO_DEVICE_INITIALIZING  - %i \n", DriverObject->Flags );

	pDeviceObj->Flags |= DO_DIRECT_IO;
	pDeviceObj->Flags &= ~DO_DEVICE_INITIALIZING;
	log( "DO_DEVICE_INITIALIZING  - %i \n", pDeviceObj->Flags );

	return STATUS_SUCCESS;
}

NTSTATUS entry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath ) {
	UNICODE_STRING driverName;
	RtlInitUnicodeString( &driverName, L"\\Driver\\Aos" );

	return IoCreateDriver( &driverName, &DriverEntry );
}