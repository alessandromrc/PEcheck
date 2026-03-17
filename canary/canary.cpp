#include "pch.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
    static bool initialized = false;

    if (reason == DLL_PROCESS_ATTACH && !initialized)
    {
        initialized = true;

        DisableThreadLibraryCalls(hModule);

        AllocConsole();

        FILE* fp = nullptr;
        freopen_s(&fp, "CONOUT$", "w", stdout);

        std::cout << "Console allocated." << std::endl;
        std::cout << "PWNED." << std::endl;

        WCHAR path[1024];
        if (GetEnvironmentVariableW(L"PECHECK_MARKER", path, static_cast<DWORD>(sizeof(path) / sizeof(WCHAR))) == 0)
            return TRUE;

        HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            static const char msg[] = "loaded";
            DWORD written = 0;
            WriteFile(f, msg, static_cast<DWORD>(sizeof(msg) - 1), &written, nullptr);
            CloseHandle(f);
        }
    }

    return TRUE;
}
