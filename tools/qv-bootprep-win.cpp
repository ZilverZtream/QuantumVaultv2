// TSK714A_System_Drive_Encryption_(PreBoot_Windows_First)_Stage1_Minifilter
// TSK714B_System_Drive_Encryption_(PreBoot_Windows_First)_Stage2_PreBoot_FullDisk

#ifdef _WIN32
#include <Windows.h>
#include <Shlwapi.h>
#include <filesystem>
#include <string>
#include <vector>
#include <cstdio>
#include "../include/qv/platform/win/qvflt_ioctl.h"
#include "../include/qv/platform/win/qvdisk_ioctl.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")

namespace fs = std::filesystem;

static const wchar_t kDiskDevicePath[] = L"\\\\.\\QvDisk";
static const wchar_t kFilterDevicePath[] = L"\\\\.\\QvFlt";
static const wchar_t kBootAppIdentifier[] = L"{fa38c01b-52b1-4b80-9be5-9b2c896cd42a}";
static const wchar_t kBootAppRelativePath[] = L"\\EFI\\QuantumVault\\qv-uefi.efi";

static void PrintUsage()
{
    wprintf(L"Usage:\n");
    wprintf(L"  qv-bootprep-win status\n");
    wprintf(L"  qv-bootprep-win install <uefi-app> <esp-root>\n");
    wprintf(L"\nArguments:\n");
    wprintf(L"  <uefi-app>  Absolute path to the signed UEFI application (qv-uefi.efi).\n");
    wprintf(L"  <esp-root>  Mounted ESP root (e.g. Z:\\).\n");
}

static bool RunProcess(const std::wstring &command, DWORD &exitCode)
{
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startupInfo = {};
    PROCESS_INFORMATION processInfo = {};
    startupInfo.cb = sizeof(startupInfo);

    if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startupInfo, &processInfo)) {
        return false;
    }

    WaitForSingleObject(processInfo.hProcess, INFINITE);
    if (!GetExitCodeProcess(processInfo.hProcess, &exitCode)) {
        exitCode = static_cast<DWORD>(-1);
    }

    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
    return exitCode == 0;
}

static bool InstallUefiApp(const fs::path &source, const fs::path &espRoot)
{
    try {
        fs::path targetDir = espRoot / L"EFI" / L"QuantumVault";
        fs::create_directories(targetDir);
        fs::path targetPath = targetDir / L"qv-uefi.efi";
        fs::copy_file(source, targetPath, fs::copy_options::overwrite_existing);
        wprintf(L"Copied UEFI application to %ls\n", targetPath.c_str());
        return true;
    } catch (const std::exception &ex) {
        printf("UEFI copy failed: %s\n", ex.what());
        return false;
    }
}

static bool EnsureBcdEntry(const std::wstring &espPartition)
{
    DWORD exitCode = 0;
    std::wstring enumCommand = L"bcdedit.exe /enum " + std::wstring(kBootAppIdentifier);
    RunProcess(enumCommand, exitCode);

    if (exitCode != 0) {
        std::wstring createCommand = L"bcdedit.exe /create " + std::wstring(kBootAppIdentifier) + L" /d \"QuantumVault Pre-Boot\" /application BOOTAPP";
        if (!RunProcess(createCommand, exitCode) || exitCode != 0) {
            wprintf(L"Failed to create BCD entry (0x%08lx)\n", exitCode);
            return false;
        }
    }

    std::wstring setDevice = L"bcdedit.exe /set " + std::wstring(kBootAppIdentifier) + L" device partition=" + espPartition;
    if (!RunProcess(setDevice, exitCode) || exitCode != 0) {
        wprintf(L"Failed to set BCD device (0x%08lx)\n", exitCode);
        return false;
    }

    std::wstring setPath = L"bcdedit.exe /set " + std::wstring(kBootAppIdentifier) + L" path " + std::wstring(kBootAppRelativePath);
    if (!RunProcess(setPath, exitCode) || exitCode != 0) {
        wprintf(L"Failed to set BCD path (0x%08lx)\n", exitCode);
        return false;
    }

    std::wstring bootSequence = L"bcdedit.exe /set {bootmgr} bootsequence " + std::wstring(kBootAppIdentifier);
    if (!RunProcess(bootSequence, exitCode) || exitCode != 0) {
        wprintf(L"Failed to update boot sequence (0x%08lx)\n", exitCode);
        return false;
    }

    return true;
}

static bool ConfigureDriverBootStart(const wchar_t *serviceName)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        wprintf(L"OpenSCManager failed (%lu)\n", GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, serviceName, SERVICE_CHANGE_CONFIG);
    if (service == nullptr) {
        wprintf(L"OpenService failed for %ls (%lu)\n", serviceName, GetLastError());
        CloseServiceHandle(scm);
        return false;
    }

    BOOL ok = ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_BOOT_START, SERVICE_ERROR_NORMAL, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!ok) {
        wprintf(L"ChangeServiceConfig failed (%lu)\n", GetLastError());
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return ok == TRUE;
}

static bool InstallPipeline(const fs::path &uefiApp, const fs::path &espRoot)
{
    if (!InstallUefiApp(uefiApp, espRoot)) {
        return false;
    }

    std::wstring partition = espRoot.root_name().wstring();
    if (partition.empty()) {
        wprintf(L"ESP root must include a drive letter (e.g. Z:)\n");
        return false;
    }

    if (partition.back() == L'\\') {
        partition.pop_back();
    }

    bool bcdOk = EnsureBcdEntry(partition);
    bool driverOk = ConfigureDriverBootStart(L"qvdisk");
    return bcdOk && driverOk;
}

static bool QueryDiskDriverStatus()
{
    HANDLE device = CreateFileW(kDiskDevicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        return false;
    }

    QVDISK_STATUS_RESPONSE status = {};
    DWORD bytesReturned = 0;
    if (DeviceIoControl(device, IOCTL_QVDISK_STATUS, nullptr, 0, &status, sizeof(status), &bytesReturned, nullptr)) {
        wprintf(L"qvdisk key loaded: %ls (recovery=%ls)\n", status.keyLoaded ? L"yes" : L"no", status.usingRecoveryKey ? L"yes" : L"no");
    } else {
        wprintf(L"Failed to query qvdisk status (%lu)\n", GetLastError());
    }

    CloseHandle(device);
    return true;
}

static bool QueryFilterDriverStatus()
{
    HANDLE device = CreateFileW(kFilterDevicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        return false;
    }

    QVFLT_STATUS_RESPONSE status = {};
    DWORD bytesReturned = 0;
    if (DeviceIoControl(device, IOCTL_QVFLT_STATUS, nullptr, 0, &status, sizeof(status), &bytesReturned, nullptr)) {
        wprintf(L"qvflt key loaded: %ls\n", status.isKeyLoaded ? L"yes" : L"no");
    }

    CloseHandle(device);
    return true;
}

static bool QueryDriverStatus()
{
    if (QueryDiskDriverStatus()) {
        return true;
    }

    if (QueryFilterDriverStatus()) {
        return true;
    }

    wprintf(L"No QuantumVault boot drivers detected\n");
    return false;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    if (_wcsicmp(argv[1], L"status") == 0) {
        QueryDriverStatus();
        return 0;
    }

    if (_wcsicmp(argv[1], L"install") == 0) {
        if (argc < 4) {
            PrintUsage();
            return 1;
        }

        fs::path uefiApp = argv[2];
        fs::path espRoot = argv[3];
        if (!fs::exists(uefiApp)) {
            wprintf(L"UEFI application not found: %ls\n", uefiApp.c_str());
            return 1;
        }
        if (!fs::exists(espRoot)) {
            wprintf(L"ESP root not accessible: %ls\n", espRoot.c_str());
            return 1;
        }

        return InstallPipeline(uefiApp, espRoot) ? 0 : 1;
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

