#pragma once
#include "Imports.h"
#include "Defs.h"
#include "Structs.h"

void _enable_write_protect_asm();

//--------------------------------------------------------------------------------------------------------
//Read Virtual Memory
//--------------------------------------------------------------------------------------------------------
void read( DWORD pId, PVOID address, size_t size, PVOID buffer, PSIZE_T retLength ) {
    MM_COPY_ADDRESS  copyMemory        = { 0 };
    KAPC_STATE       State             = { 0 };
    PEPROCESS        currentProcess    = 0;
    NTSTATUS         state             = 0;

    state = PsLookupProcessByProcessId( pId, &currentProcess );
    if ( !NT_SUCCESS( state )) {
        err( "Error PsLookupProcessByProcessId status %i \n", state );
        return;
    }

    log( "pId %i PEPROCESS %p \n", pId, currentProcess );

    __try {

        copyMemory.VirtualAddress = address;
        MmCopyMemory( buffer, copyMemory, size, MM_COPY_MEMORY_VIRTUAL, retLength );
        log( "buffer %p retSize %i \n", buffer, *retLength );

    }
    __except ( EXCEPTION_EXECUTE_HANDLER ) {
        ObDereferenceObject( currentProcess );
        err( "Exception ! \n" );
        return;
    }

    ObDereferenceObject( currentProcess );
}

//--------------------------------------------------------------------------------------------------------
//Write Virtual Memory
//--------------------------------------------------------------------------------------------------------
void write( DWORD pId, PVOID dstAddress, PVOID srcAddress, size_t size ) {
    NTSTATUS               ntStatus = 0;
    PEPROCESS              pCurrentPEprocess;
    MM_COPY_ADDRESS        copyMemory;

    log( "Entry of write memory ! \n" );

    ntStatus = PsLookupProcessByProcessId( pId, &pCurrentPEprocess );
    if ( !NT_SUCCESS( ntStatus ) ) {
        err( "Error PsLookupProcessByProcessId %i \n", ntStatus );
        ObDereferenceObject( pCurrentPEprocess );
        return;
    }

    __try {
        SIZE_T ret;
        ntStatus = MmCopyVirtualMemory( IoGetCurrentProcess(), srcAddress, pCurrentPEprocess, dstAddress, size, KernelMode, &ret );
        if ( !NT_SUCCESS( ntStatus ) ) {
            err( "Error MmCopyVirtualMemory %lu\n", ntStatus);
            ObDereferenceObject( pCurrentPEprocess );
            return;
        }
        log( "Write len -  %i, address -  %p \n", ret, dstAddress);

    }
    __except ( 1 ) {
        err( "Exception code %lu - \n",GetExceptionCode() );
        ObDereferenceObject( pCurrentPEprocess );
        return;
    }

    ObDereferenceObject( pCurrentPEprocess );
}

//--------------------------------------------------------------------------------------------------------
//Change usermode process memory protect
//--------------------------------------------------------------------------------------------------------
void change_virtual_mem_protect( DWORD pId, PVOID address, size_t size, ULONG newProtect,DWORD* oldProtect ) {
    NTSTATUS    ntStatus = 0;
    PEPROCESS   pProcess = 0;
    KAPC_STATE  apc = { 0 };

    log( "change_virtual_mem_protect entry ! \n" );

    ntStatus = PsLookupProcessByProcessId( pId, &pProcess );
    if ( !NT_SUCCESS( ntStatus ) ) {
        err( "Error PsLookupProcessByProcessId %i \n", ntStatus );
        return;
    }

    __try {
        KeStackAttachProcess( pProcess, &apc );

        DWORD old;
        ZwProtectVirtualMemory( ( HANDLE )-1, ( PVOID* )&address, &size, newProtect, oldProtect );

        log( "Changr protect success ! pId - %i ! \n",pId );

        KeUnstackDetachProcess( &apc );
    }
    __except ( 1 ) {
        err( "Exception ! code %lu \n", GetExceptionCode() );
        ObDereferenceObject( pProcess );
        return;
    }

    log( "change_virtual_mem_protect end ! \n" );
    ObDereferenceObject( pProcess );
}

//--------------------------------------------------------------------------------------------------------
//Get pName by id
//--------------------------------------------------------------------------------------------------------
char* get_process_name_by_id( HANDLE pid ) {
    NTSTATUS status;
    PEPROCESS EProcess = NULL;
    status = PsLookupProcessByProcessId( pid, &EProcess );

    if ( !NT_SUCCESS( status ) ) {
        return FALSE;
    }
    ObDereferenceObject( EProcess );
    return ( char* )PsGetProcessImageFileName( EProcess );
}

//--------------------------------------------------------------------------------------------------------
//Get module image base by name
//--------------------------------------------------------------------------------------------------------
uintptr_t get_pid_by_name(const char* imagename ) {
    NTSTATUS status;
    PRTL_PROCESS_MODULES ModuleInfo;

    ModuleInfo = ExAllocatePool( PagedPool, 1024 * 1024 ); // Allocate memory for the module list

    if ( !ModuleInfo ) {
        DbgPrintEx( DPFLTR_IHVDRIVER_ID, -1, "Fail\r\n" );
        return -1;
    }

    if ( !NT_SUCCESS( status = ZwQuerySystemInformation( 11, ModuleInfo, 1024 * 1024, NULL ) ) ) // 11 = SystemModuleInformation
    {
        DbgPrintEx( DPFLTR_IHVDRIVER_ID, -1, "Fail 2\r\n" );
        ExFreePool( ModuleInfo );
        return -1;
    }

    for ( int i = 0; i < ModuleInfo->NumberOfModules; i++ ) {
        if ( !strcmp( ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName, imagename ) ) {
            DbgPrintEx( DPFLTR_IHVDRIVER_ID, -1, "Found %s\r\n", imagename );
            return ModuleInfo->Modules[i].ImageBase;
        }

    }

    ExFreePool( ModuleInfo );

    return 0;
}


void write_to_read_only_memory( PVOID dst, PVOID src, SIZE_T size ) {
    PMDL mdl = IoAllocateMdl( dst, ( ULONG )size, FALSE, FALSE, NULL );

    if ( !mdl )
        return;

    MmProbeAndLockPages( mdl, KernelMode, IoReadAccess );
    PVOID mapping = MmMapLockedPagesSpecifyCache( mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority );
    MmProtectMdlSystemAddress( mdl, PAGE_READWRITE );

    RtlCopyMemory( mapping, src, size );

    MmUnmapLockedPages( mapping, mdl );
    MmUnlockPages( mdl );
    IoFreeMdl( mdl );

    return;
}