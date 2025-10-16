// TSK714A_System_Drive_Encryption_(PreBoot_Windows_First)_Stage1_Minifilter

#ifdef _WIN32
#include <Windows.h>
#include <stdio.h>
#include "../include/qv/platform/win/qvflt_ioctl.h"

static void PrintUsage()
{
    puts("Usage: qv-bootprep-win install|status");
}

static bool QueryDriverStatus()
{
    HANDLE device = CreateFileW(L"\\\\.\\QvFlt", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        puts("Driver not available");
        return false;
    }

    QVFLT_STATUS_RESPONSE status = {};
    DWORD bytesReturned = 0;
    if (DeviceIoControl(device, IOCTL_QVFLT_STATUS, nullptr, 0, &status, sizeof(status), &bytesReturned, nullptr)) {
        printf("Driver key loaded: %s\n", status.isKeyLoaded ? "yes" : "no");
    }

    CloseHandle(device);
    return true;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    if (lstrcmpiW(argv[1], L"status") == 0) {
        QueryDriverStatus();
        return 0;
    }

    if (lstrcmpiW(argv[1], L"install") == 0) {
        puts("Installation routine placeholder");
        return 0;
    }

    PrintUsage();
    return 1;
}

#else
int main()
{
    return 0;
}
#endif

