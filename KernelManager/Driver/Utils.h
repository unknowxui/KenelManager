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




PVOID GetSystemModBase( LPCSTR modName ) {
    ULONG bytes = 0;
    NTSTATUS status = ZwQuerySystemInformation( SystemModuleInformation, NULL, bytes, &bytes );

    if ( !bytes )
        return NULL;

    PRTL_PROCESS_MODULES modules = ( PRTL_PROCESS_MODULES )ExAllocatePool( NonPagedPool, bytes );

    status = ZwQuerySystemInformation( SystemModuleInformation, modules, bytes, &bytes );

    if ( !NT_SUCCESS( status ) )
        return NULL;



    PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
    PVOID module_base = 0, module_size = 0;

    for ( ULONG i = 0; i < modules->NumberOfModules; i++ ) {
        if ( !strcmp( ( char* )module[i].FullPathName, modName ) ) {
            module_base = module[i].ImageBase;
            module_size = ( PVOID )module[i].ImageSize;
            break;
        }
    }

    if ( modules )
        ExFreePool( modules );

    if ( module_base <= NULL )
        return NULL;

    return module_base;
}
PVOID GetSystemModuleExport( LPCSTR modName, LPCSTR routineName ) {
    PVOID lpModule = GetSystemModBase( modName );

    if ( !lpModule )
        return NULL;

    return RtlFindExportedRoutineByName( lpModule, routineName );
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
const char* Harz4StrCrypt( char str[] ) {
    for ( int i = 0; i < strlen( str ); i++ )
        str[i] += 4;

    return str;
}
const wchar_t* Harz4StrCryptW( wchar_t str[] ) {
    for ( int i = 0; i < wcslen( str ); i++ )
        str[i] += 4;

    return str;
}
void HookFunction( PVOID src, LPCSTR funcName ) {
    if ( !src )
        return;

    // \\SystemRoot\\System32\\drivers\\dxgkrnl.sys
    PVOID* origFunction = ( PVOID* )GetSystemModuleExport( Harz4StrCrypt( "XOuopaiNkkpXOuopai/.X`neranoX`tcgnjh*ouo" ), funcName );

    if ( !origFunction )
        return;

    UINT_PTR hookAddr = ( UINT_PTR )src;

    BYTE movInst[2] = { 0x48, 0xBA }; // mov rdx,  
    BYTE jmpInst[2] = { 0xFF, 0xE2 }; // jmp rdx

    BYTE originalInstructions[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x48, 0x08, 0x53, 0x56, 0x57 };
    BYTE shellcodeEnd[] = { 0x5B, 0x5E, 0x5F, 0x48, 0x83, 0xC0, 0x19, 0x48, 0xFF, 0xC0, 0x48, 0x39, 0xD0, 0x48, 0x83, 0xE8, 0x19, 0x48, 0x39, 0xD8, 0x48, 0xFF, 0xC8, 0x48, 0x39, 0xC1, 0x48, 0x81, 0xE9,
        0x69, 0x69, 0x00, 0x00, 0x48, 0x39, 0xD9, 0x48, 0x81, 0xC1, 0x69, 0x69, 0x00, 0x00, 0xFF, 0xE2 };
    BYTE newInstructions[68] = { 0x0 };

    RtlSecureZeroMemory( &newInstructions, sizeof( newInstructions ) );

    memcpy( ( PVOID )(( UINT_PTR )newInstructions), &originalInstructions, sizeof( originalInstructions ) );
    memcpy( ( PVOID )(( UINT_PTR )newInstructions + sizeof( originalInstructions )), &movInst, sizeof( movInst ) );
    memcpy( ( PVOID )(( UINT_PTR )newInstructions + sizeof( originalInstructions ) + sizeof( movInst )), &hookAddr, sizeof( hookAddr ) );
    memcpy( ( PVOID )(( UINT_PTR )newInstructions + sizeof( originalInstructions ) + sizeof( movInst ) + sizeof( hookAddr )), &shellcodeEnd, sizeof( shellcodeEnd ) );
    memcpy( ( PVOID )(( UINT_PTR )newInstructions + sizeof( originalInstructions ) + sizeof( movInst ) + sizeof( hookAddr ) + sizeof( shellcodeEnd )), &jmpInst, sizeof( jmpInst ) );

    write_to_read_only_memory( origFunction, &newInstructions, sizeof( newInstructions ) );

    return;
}