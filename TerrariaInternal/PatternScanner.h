#pragma once
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>

typedef unsigned char byte;
struct MemoryRegion
{
    uintptr_t baseAddress;
    SIZE_T regionSize;
};

class PatternScanner
{
public:

    uintptr_t FindPattern(uintptr_t base, uintptr_t size, wchar_t pattern[], wchar_t mask[])
    {
        for (uintptr_t retAddress = base; retAddress < (base + size - wcslen(mask)); retAddress++)
        {
            if (*(BYTE*)retAddress == (pattern[0] & 0xff) || mask[0] == '?')
            {
                uintptr_t startSearch = retAddress;
                for (int i = 0; mask[i] != '\0'; i++, startSearch++)
                {
                    if ((pattern[i] & 0xff) != *(BYTE*)startSearch && mask[i] != '?')
                        break;

                    if (((pattern[i] & 0xff) == *(BYTE*)startSearch || mask[i] == '?') && mask[i + 1] == '\0')
                        return retAddress;
                }
            }
        }

        return NULL;
    }
    uintptr_t GetSizeOfAllocation(HANDLE hProcess, uintptr_t* pAddress)
    {
        uintptr_t dwTemp = (uintptr_t)pAddress;
        MEMORY_BASIC_INFORMATION info;

        ZeroMemory(&info, sizeof(info));

        uintptr_t dwSize = 0;
        while (true)
        {
            if (VirtualQueryEx(hProcess, (LPCVOID)dwTemp, &info, sizeof(info)) == 0)
                break;

            if ((uintptr_t)info.AllocationBase == (uintptr_t)pAddress)
            {
                dwSize += info.RegionSize;
                dwTemp += info.RegionSize;
            }
            else
                break;
        }

        return dwSize;
    }

    std::vector<MemoryRegion> QueryMemoryRegions(DWORD processId)
    {
        std::vector<MemoryRegion> regions;

        HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (processHandle == NULL)
        {
            std::cout << "Failed to open the target process." << std::endl;
            return regions;
        }

        uintptr_t baseAddress = 0;
        MEMORY_BASIC_INFORMATION mbi;
        while (VirtualQueryEx(processHandle, (LPCVOID)baseAddress, &mbi, sizeof(mbi)) != 0)
        {
            if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS)
            {
                MemoryRegion region;
                region.baseAddress = (uintptr_t)mbi.BaseAddress;
                region.regionSize = mbi.RegionSize;
                regions.push_back(region);
            }

            baseAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }

        CloseHandle(processHandle);

        return regions;
    }

    uintptr_t GetAddressFromSignature(DWORD processID, uintptr_t base, uintptr_t size, std::vector<int> signature) {
        std::cout << "Attempting to find Pattern starting at: " << std::hex << base << std::endl;
        std::vector<byte> memBuffer(size);
        if (!Toolhelp32ReadProcessMemory(processID, (LPCVOID)(base), memBuffer.data(), size, NULL)) {
            std::cout << GetLastError() << std::endl;
            // return NULL;
        }
        for (int i = 0; i < size; i++) {
            for (uintptr_t j = 0; j < signature.size(); j++) {
                if (signature.at(j) != -1 && signature[j] != memBuffer[i + j])
                    //std::cout << std::hex << signature.at(j) << std::hex << memBuffer[i + j] << std::endl;
                    break;
                if (signature[j] == memBuffer[i + j] && j > 0)
                    std::cout << std::hex << int(signature[j]) << std::hex << int(memBuffer[i + j]) << j << std::endl;
                if (j + 1 == signature.size())
                    return base + i;
            }
        }
        return NULL;
    }


    void ReadProcessMemorySafe(HANDLE hProcess, LPCVOID lpAddress, LPVOID lpBuffer, SIZE_T size)
    {
        SIZE_T tempSize,
            bytesRead;

        do
        {
            // lazy shitty way to read a module with invalid pages

            tempSize = min(size, 0x1000);

            ReadProcessMemory(hProcess, lpAddress, lpBuffer, tempSize, &bytesRead);

            size -= tempSize;
            lpAddress = (LPCVOID)((DWORD)lpAddress + tempSize);
            lpBuffer = (LPVOID)((DWORD)lpBuffer + tempSize);

        } while (size != 0);
    }

    uintptr_t FindPatternInMemory(const std::vector<byte>& memBuffer, const std::vector<int>& signature)
    {
        for (size_t i = 0; i < memBuffer.size(); i++)
        {
            bool found = true;
            for (size_t j = 0; j < signature.size(); j++)
            {
                if (signature[j] != -1 && signature[j] != memBuffer[i + j])
                {
                    found = false;
                    break;
                }
            }

            if (found)
            {
                return i;
            }
        }

        return NULL;
    }

    uintptr_t FindPatternInMemoryRegions(HANDLE hProcess, const std::vector<MemoryRegion>& memoryRegions,
        const std::vector<int>& signature)
    {
        for (const MemoryRegion& region : memoryRegions)
        {
            std::vector<byte> memBuffer(region.regionSize);
            if (!ReadProcessMemory(hProcess, (LPCVOID)region.baseAddress, memBuffer.data(), region.regionSize, NULL))
            {
                continue;
            }

            uintptr_t offset = FindPatternInMemory(memBuffer, signature);
            if (offset != NULL)
            {
                std::cout << "Found Pattern at: " << std::hex << region.baseAddress + offset << std::endl;
                return region.baseAddress + offset;
            }
        }

        return NULL;
    }
    uintptr_t GetAddressFromSignature(HANDLE hProcess, uintptr_t base, uintptr_t size, std::vector<int> signature) {
        std::cout << "Attempting to find Pattern starting at: " << std::hex << base << std::endl;
        std::vector<byte> memBuffer(size);
        if (!ReadProcessMemory(hProcess, (LPCVOID)(base), memBuffer.data(), size, NULL)) {
            std::cout << GetLastError() << std::endl;
            // return NULL;
        }
        for (int i = 0; i < size; i++) {
            for (uintptr_t j = 0; j < signature.size(); j++) {
                if (signature.at(j) != -1 && signature[j] != memBuffer[i + j])
                    //std::cout << std::hex << signature.at(j) << std::hex << memBuffer[i + j] << std::endl;
                    break;
                if (signature[j] == memBuffer[i + j] && j > 0)
                    std::cout << std::hex << int(signature[j]) << std::hex << int(memBuffer[i + j]) << j << std::endl;
                if (j + 1 == signature.size())
                    return base + i;
            }
        }
        return NULL;
    }
    std::vector<int> CreateSignature(const wchar_t* pattern, const wchar_t* mask)
    {
        std::vector<int> signature;

        for (int i = 0; mask[i] != '\0'; i++)
        {
            if (mask[i] == 'x')
            {
                signature.push_back(pattern[i] & 0xFF);
            }
            else
            {
                signature.push_back(-1);
            }
        }

        return signature;
    }
};