#include "pch.h"
#include <Windows.h>
#include <cstdio>
#include "PatternScanner.h"
#include <tchar.h>
#include "Offsets.h"


// GetPlayer hooks
typedef void* (*tGetLocalPlayer)();
tGetLocalPlayer oGetLocalPlayer;

void* h_getLocalPlayer()
{
    void* result = oGetLocalPlayer();
    return result;
}
void HookFunction(tGetLocalPlayer targetFunction)
{
    oGetLocalPlayer = targetFunction;
    targetFunction = &h_getLocalPlayer;
}

DWORD WINAPI Entry(LPVOID lpParam)
{
 
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    wchar_t pattern[] = L"\xa1\x00\x00\x00\x00\x8b\x15\x00\x00\x00\x00\x3b\x50\x00\x73\x00\x8b\x44\x90\x00\xc3";
    wchar_t mask[] = L"x????xx????xx?x?xxx?x";

    // Pattern Scan to find addr
    PatternScanner pScanner;
    HANDLE hProc = GetCurrentProcess();
    std::cout << "Scanning for pattern\n";

    // partial header workaround
    std::vector<MemoryRegion> regions = pScanner.QueryMemoryRegions(GetCurrentProcessId());
   
    // scan pattern
    uintptr_t funcAddr = pScanner.FindPatternInMemoryRegions(hProc, regions, pScanner.CreateSignature(pattern, mask));

    // get function ptr
    tGetLocalPlayer getLocalPlayer = reinterpret_cast<tGetLocalPlayer>(funcAddr);

    // Hook the function
    HookFunction(getLocalPlayer);

    // Call the hooked function
    void* localPlayer = getLocalPlayer();

    std::cout << "Address of localPlayer: " << localPlayer << std::endl;

    // store player
    Player* player = reinterpret_cast<Player*>(localPlayer);

    bool exit = false;

    // working loop
    while (!exit)
    {
        player->playerHealth = 1337;
        WORD check = GetAsyncKeyState(VK_F2);
        if ((check & 0x8000) == 0x8000)
        {
            std::cout << "Unloading\n";
            exit = true;

        }
    }

    // clear resources for dll unload

    player = nullptr;
    FreeConsole();
    HMODULE hModule = static_cast<HMODULE>(lpParam);
    FreeLibraryAndExitThread(hModule, 0);




}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            // can't use _beginthreadex here, as I can't release its resources for some reason .. hmm 
            CreateThread(NULL, 0, Entry, hModule, NULL, nullptr);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

