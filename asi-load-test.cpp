#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <cwchar>

namespace {

bool GetFileSize(const wchar_t* path, LARGE_INTEGER& size) {
    HANDLE file = CreateFileW(path, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        size.QuadPart = 0;
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    }

    const bool succeeded = GetFileSizeEx(file, &size) != FALSE;
    CloseHandle(file);
    return succeeded;
}

bool AppendedLogContains(const wchar_t* path, LONGLONG offset,
                         const char* expectedText) {
    HANDLE file = CreateFileW(path, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER position{};
    position.QuadPart = offset;
    if (SetFilePointerEx(file, position, nullptr, FILE_BEGIN) == FALSE) {
        CloseHandle(file);
        return false;
    }

    char appended[4096]{};
    DWORD bytesRead = 0;
    const bool readSucceeded =
        ReadFile(file, appended, sizeof(appended) - 1, &bytesRead, nullptr) != FALSE;
    CloseHandle(file);
    return readSucceeded && strstr(appended, expectedText) != nullptr;
}

bool BuildSiblingPath(const wchar_t* modulePath, const wchar_t* filename,
                      wchar_t (&output)[MAX_PATH]) {
    const DWORD length = GetFullPathNameW(modulePath, MAX_PATH, output, nullptr);
    if (length == 0 || length >= MAX_PATH) {
        return false;
    }

    wchar_t* slash = wcsrchr(output, L'\\');
    if (slash == nullptr) {
        return false;
    }
    slash[1] = L'\0';
    return wcscat_s(output, filename) == 0;
}

}  // namespace

int wmain(int argumentCount, wchar_t** arguments) {
    if (argumentCount != 2 && argumentCount != 3) {
        std::fwprintf(stderr,
                      L"Usage: asi-load-test.exe <path-to-Dishonored2HighFPSFix.asi> "
                      L"[--layout-host]\n");
        return 2;
    }
    const bool layoutHost =
        argumentCount == 3 && wcscmp(arguments[2], L"--layout-host") == 0;
    if (argumentCount == 3 && !layoutHost) {
        std::fwprintf(stderr, L"Unknown test option: %ls\n", arguments[2]);
        return 2;
    }
    const char* expectedDiagnostic = layoutHost ?
        "Executable layout does not match a known layout profile" :
        "Host executable is not Dishonored2.exe";

    wchar_t logPath[MAX_PATH]{};
    if (!BuildSiblingPath(arguments[1], L"d2-high-fps-fix.log", logPath)) {
        std::fwprintf(stderr, L"Unable to derive the plugin's sibling log path.\n");
        return 3;
    }

    LARGE_INTEGER initialLogSize{};
    if (!GetFileSize(logPath, initialLogSize)) {
        std::fwprintf(stderr, L"Unable to inspect the initial log size: %lu\n",
                      GetLastError());
        return 4;
    }

    HMODULE plugin = LoadLibraryW(arguments[1]);
    if (plugin == nullptr) {
        std::fwprintf(stderr, L"LoadLibraryW failed for the ASI: %lu\n",
                      GetLastError());
        return 5;
    }

    if (GetProcAddress(plugin, "DirectInput8Create") != nullptr) {
        std::fwprintf(stderr,
                      L"The ASI unexpectedly exports DirectInput8Create.\n");
        return 6;
    }

    LARGE_INTEGER currentLogSize{};
    bool diagnosticWritten = false;
    for (unsigned int attempt = 0; attempt < 100; ++attempt) {
        if (!GetFileSize(logPath, currentLogSize)) {
            std::fwprintf(stderr, L"Unable to inspect the plugin log: %lu\n",
                          GetLastError());
            return 7;
        }
        if (currentLogSize.QuadPart > initialLogSize.QuadPart &&
            AppendedLogContains(logPath, initialLogSize.QuadPart,
                                expectedDiagnostic)) {
            diagnosticWritten = true;
            break;
        }
        Sleep(50);
    }

    if (!diagnosticWritten) {
        std::fwprintf(stderr,
                      L"The ASI did not write its expected unsupported-host diagnostic.\n");
        return 8;
    }

    // Do not call FreeLibrary: the production plugin is process-lifetime and
    // intentionally has no live-unload/unhook contract.
    std::wprintf(L"ASI load, no-proxy-export, sibling-log, and %ls fail-closed "
                 L"checks passed.\n",
                 layoutHost ? L"layout" : L"host-identity");
    return 0;
}
