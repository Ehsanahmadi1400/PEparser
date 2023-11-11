// myStructs.h
#ifndef MY_STRUCTS_H
#define MY_STRUCTS_H

#include <iostream>


// Define the DOS header structure, (Identical in 32 & 64 architectures)
struct DosHeader {
    uint16_t e_magic;       // "MZ" signature
    uint16_t e_cblp;        // Bytes on last page of file
    uint16_t e_cp;          // Pages in file
    uint16_t e_crlc;        // Relocations
    uint16_t e_cparhdr;     // Size of header in paragraphs
    uint16_t e_minalloc;    // Minimum extra paragraphs needed
    uint16_t e_maxalloc;    // Maximum extra paragraphs needed
    uint16_t e_ss;          // Initial (relative) SS value
    uint16_t e_sp;          // Initial SP value
    uint16_t e_csum;        // Checksum
    uint16_t e_ip;          // Initial IP value
    uint16_t e_cs;          // Initial (relative) CS value
    uint16_t e_lfarlc;      // File address of relocation table
    uint16_t e_ovno;        // Overlay number
    uint16_t e_res[4];      // Reserved words
    uint16_t e_oemid;       // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;     // OEM information; e_oemid specific
    uint16_t e_res2[10];    // Reserved words
    int32_t e_lfanew;       // Offset to the NT header
};

// Define the NT header structure
struct NtHeader {
  uint32_t Signature; // "PE\0\0" signature
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

// Define the File header structure
struct FileHeader {
  uint32_t Signature; // "PE\0\0" signature
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

// Define the Optional header structure (Compaitable for PE32 and PE32+)
struct OptionalHeader {
  uint16_t Magic;               // PE32 (0x10b) or PE32+ (0x20b)
  uint8_t MajorLinkerVersion;
  uint8_t MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  // Differences between PE32 and PE32+
  uint64_t ImageBase;  // 32-bit in PE32, 64-bit in PE32+
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32Version;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;  // 32-bit in PE32, 64-bit in PE32+
  uint64_t SizeOfStackCommit;   // 32-bit in PE32, 64-bit in PE32+
  uint64_t SizeOfHeapReserve;   // 32-bit in PE32, 64-bit in PE32+
  uint64_t SizeOfHeapCommit;    // 32-bit in PE32, 64-bit in PE32+
  uint32_t ReserveSize;         // 16-bit in PE32, 32-bit in PE32+
};

// Define the Section header structure
struct SectionHeader {
  char Name[8];              // Section name
  uint32_t VirtualSize;      // Size of the section in virtual memory
  uint32_t VirtualAddress;   // Virtual address of the section in memory
  uint32_t SizeOfRawData;    // Size of the section in raw data on disk
  uint32_t FileOffset;       // Offset of the section in the PE file
  uint32_t Flags;            // Section flags (architecture-specific bits might exist)
  uint16_t Characteristics;  // Section characteristics (architecture-specific bits might exist)
};


#endif // MY_STRUCTS_H