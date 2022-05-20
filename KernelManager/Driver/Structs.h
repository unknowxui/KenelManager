#pragma once
#include <wdm.h>


typedef struct _READ_MEMORY {
	PVOID        address;
	size_t       size;
	unsigned int pId;
	wchar_t*     procName;
} READ_MEMORY,*PREAD_MEMORY;

typedef struct _WRITE_MEMORY {
	PVOID        srcAddress;
	PVOID        wAddress;
	size_t       wSize;
	unsigned int pId;
}WRITE_MEMORY,*PWRITE_MEMORY;

typedef struct _CHANGE_PROTECT {
	PVOID address;
	size_t size;
	ULONG newProtect;
	unsigned int pId;
	DWORD* oldProtect;

}CHANGE_PROTECT, * PCHANGE_PROTECT;

typedef struct _ALLOCATE_MEMORY {
	unsigned int pId;
	PVOID* allocateBase;
	PSIZE_T size;
	ULONG protect;
	ULONG allcoateType;
}ALLOCATE_MEMORY, * PALLOCATE_MEMORY;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;