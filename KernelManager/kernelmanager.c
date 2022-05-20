#include <ntstatus.h>

#include "Driver/Utils.h"
#include "Driver/Structs.h"

NTSTATUS __fastcall hook( PVOID a ) {
	log( "%p \n", a );

	return STATUS_SUCCESS;
}



NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath ) {

	NTSTATUS ntStatus         = 0;
	PDEVICE_OBJECT pDeviceObj = 0;

	UNICODE_STRING dosDeviceName = RTL_CONSTANT_STRING( L"\\DosDevices\\Aos") ;
	UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Device\\Aos" );



	//ntStatus = IoCreateDevice( DriverObject,
	//	0,
	//	&driverName,
	//	FILE_DEVICE_UNKNOWN,
	//	FILE_DEVICE_SECURE_OPEN,
	//	FALSE,
	//	&pDeviceObj );

	log( "%i %i \n", dosDeviceName.Length, driverName.Length );

	if ( !NT_SUCCESS( ntStatus ) ) {
		err( "ntStatus = %i IoCreateDevice Error ! \n", ntStatus );
		return ntStatus;
	}

	SetFlag( pDeviceObj->Flags, DO_BUFFERED_IO );

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