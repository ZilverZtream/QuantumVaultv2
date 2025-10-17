// TSK714A_System_Drive_Encryption_(PreBoot_Windows_First)_Stage1_Minifilter
// TSK714B_System_Drive_Encryption_(PreBoot_Windows_First)_Stage2_PreBoot_FullDisk

#ifdef _WIN32
#include <Windows.h>
#include "../../include/qv/platform/win/qvflt_ioctl.h"
#include "../../include/qv/platform/win/qvdisk_ioctl.h"
#include <string>

#pragma comment(lib, "Advapi32.lib")

static SERVICE_STATUS_HANDLE g_ServiceStatusHandle = nullptr;
static HANDLE g_StopEvent = nullptr;
static HANDLE g_DeviceHandle = nullptr;
static BOOL g_UsingDiskDriver = FALSE;

static const wchar_t kFilterDevicePath[] = L"\\\\.\\QvFlt";
static const wchar_t kDiskDevicePath[] = L"\\\\.\\QvDisk";
static const wchar_t kFirmwareVariableName[] = L"QVKey";
static const wchar_t kFirmwareVariableGuid[] = L"{d16a4c54-0f07-4a28-9a5e-5de41a3b928c}";
static const wchar_t kRecoveryKeyPath[] = L"C:\\ProgramData\\QuantumVault\\recovery.qvkey";

#define QV_EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002

static BOOL QvEnableFirmwareVariablePrivilege()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return FALSE;
    }

    TOKEN_PRIVILEGES privileges = {};
    LUID luid = {};
    BOOL result = FALSE;

    if (LookupPrivilegeValueW(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &luid)) {
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
        DWORD error = GetLastError();
        if (adjusted && error == ERROR_SUCCESS) {
            result = TRUE;
        }
    }

    CloseHandle(token);
    return result;
}

static VOID WINAPI QvServiceMain(DWORD argc, LPWSTR *argv);
static DWORD WINAPI QvServiceCtrlHandlerEx(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context);
static DWORD WINAPI QvServiceWorker(LPVOID context);

static BOOL QvSendKeyToDriver(HANDLE device, const QVFLT_KEY_REQUEST &request)
{
    DWORD bytesReturned = 0;
    return DeviceIoControl(device, IOCTL_QVFLT_SET_KEY, (LPVOID)&request, sizeof(request), nullptr, 0, &bytesReturned, nullptr);
}

static VOID QvSecureZero(void *buffer, size_t length)
{
    if (buffer == nullptr) {
        return;
    }

    volatile unsigned char *ptr = reinterpret_cast<volatile unsigned char *>(buffer);
    while (length-- > 0) {
        *ptr++ = 0;
    }
}

static BOOL QvSendDiskSessionKey(HANDLE device, const QVDISK_SESSION_KEY &session, BOOL usingRecovery)
{
    QVDISK_IMPORT_SESSION_KEY_REQUEST request = {};
    request.sessionKey = session;
    if (usingRecovery) {
        request.sessionKey.flags |= QVDISK_IMPORT_FLAG_RECOVERY_KEY;
    }
    request.nonce = GetTickCount();

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(device, IOCTL_QVDISK_IMPORT_SESSION_KEY, &request, sizeof(request), nullptr, 0, &bytesReturned, nullptr);
    QvSecureZero(&request, sizeof(request));
    return result;
}

static BOOL QvClearFirmwareSessionKey()
{
    return SetFirmwareEnvironmentVariableExW(kFirmwareVariableName, kFirmwareVariableGuid, nullptr, 0, QV_EFI_VARIABLE_BOOTSERVICE_ACCESS);
}

static BOOL QvLoadFirmwareSessionKey(QVDISK_SESSION_KEY &session)
{
    DWORD attributes = 0;
    DWORD bytesRead = GetFirmwareEnvironmentVariableExW(kFirmwareVariableName, kFirmwareVariableGuid, &session, sizeof(session), &attributes);
    if (bytesRead != sizeof(session)) {
        QvSecureZero(&session, sizeof(session));
        return FALSE;
    }
    return TRUE;
}

static BOOL QvLoadRecoveryKeyFromFile(QVDISK_RECOVERY_KEY_BLOB &blob)
{
    HANDLE file = CreateFileW(kRecoveryKeyPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    BYTE buffer[QVDISK_RECOVERY_KEY_BYTES] = {};
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(file, buffer, sizeof(buffer), &bytesRead, nullptr);
    CloseHandle(file);

    if (!ok || bytesRead == 0) {
        QvSecureZero(buffer, sizeof(buffer));
        return FALSE;
    }

    if (bytesRead > sizeof(blob.key)) {
        bytesRead = sizeof(blob.key);
    }

    CopyMemory(blob.key, buffer, bytesRead);
    blob.size = bytesRead;
    blob.version = 1;
    QvSecureZero(buffer, sizeof(buffer));
    return TRUE;
}

static BOOL QvEnrollRecoveryKey(HANDLE device)
{
    QVDISK_RECOVERY_KEY_BLOB blob = {};
    if (!QvLoadRecoveryKeyFromFile(blob)) {
        return FALSE;
    }

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(device, IOCTL_QVDISK_ENROLL_RECOVERY, &blob, sizeof(blob), nullptr, 0, &bytesReturned, nullptr);
    QvSecureZero(&blob, sizeof(blob));
    return ok;
}

static VOID QvHandlePowerEvent(DWORD eventType)
{
    if (g_DeviceHandle == nullptr || !g_UsingDiskDriver) {
        return;
    }

    switch (eventType) {
    case PBT_APMSUSPEND:
        DeviceIoControl(g_DeviceHandle, IOCTL_QVDISK_LOCK, nullptr, 0, nullptr, 0, nullptr, nullptr);
        break;
    case PBT_APMRESUMEAUTOMATIC:
    {
        QVDISK_SESSION_KEY session = {};
        if (QvEnableFirmwareVariablePrivilege() && QvLoadFirmwareSessionKey(session)) {
            QvSendDiskSessionKey(g_DeviceHandle, session, FALSE);
            QvClearFirmwareSessionKey();
        }
        QvSecureZero(&session, sizeof(session));
        break;
    }
    default:
        break;
    }
}

static VOID ReportServiceStatus(DWORD currentState, DWORD exitCode)
{
    SERVICE_STATUS status = {};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    if (currentState == SERVICE_START_PENDING) {
        status.dwControlsAccepted = 0;
    } else {
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT | SERVICE_ACCEPT_PRESHUTDOWN;
    }
    status.dwCurrentState = currentState;
    status.dwWin32ExitCode = exitCode;
    SetServiceStatus(g_ServiceStatusHandle, &status);
}

static DWORD WINAPI QvServiceCtrlHandlerEx(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context)
{
    UNREFERENCED_PARAMETER(eventData);
    UNREFERENCED_PARAMETER(context);

    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_PRESHUTDOWN:
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR);
        if (g_StopEvent != nullptr) {
            SetEvent(g_StopEvent);
        }
        break;
    case SERVICE_CONTROL_POWEREVENT:
        QvHandlePowerEvent(eventType);
        break;
    default:
        break;
    }

    return NO_ERROR;
}

static VOID WINAPI QvServiceMain(DWORD argc, LPWSTR *argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_ServiceStatusHandle = RegisterServiceCtrlHandlerExW(L"qvsvc", QvServiceCtrlHandlerEx, nullptr);
    if (g_ServiceStatusHandle == nullptr) {
        return;
    }

    g_StopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (g_StopEvent == nullptr) {
        ReportServiceStatus(SERVICE_STOPPED, GetLastError());
        return;
    }

    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR);

    HANDLE workerThread = CreateThread(nullptr, 0, QvServiceWorker, nullptr, 0, nullptr);
    if (workerThread != nullptr) {
        WaitForSingleObject(workerThread, INFINITE);
        CloseHandle(workerThread);
    }

    if (g_StopEvent != nullptr) {
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
    }

    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR);
}

static DWORD WINAPI QvServiceWorker(LPVOID context)
{
    UNREFERENCED_PARAMETER(context);

    HANDLE device = CreateFileW(kDiskDevicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    g_UsingDiskDriver = TRUE;

    if (device == INVALID_HANDLE_VALUE) {
        device = CreateFileW(kFilterDevicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        g_UsingDiskDriver = FALSE;
    }

    if (device == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    g_DeviceHandle = device;

    if (g_UsingDiskDriver) {
        QVDISK_SESSION_KEY session = {};
        if (QvEnableFirmwareVariablePrivilege() && QvLoadFirmwareSessionKey(session)) {
            QvSendDiskSessionKey(device, session, FALSE);
            QvClearFirmwareSessionKey();
        }
        QvEnrollRecoveryKey(device);
        QvSecureZero(&session, sizeof(session));
    } else {
        QVFLT_KEY_REQUEST keyRequest = {};
        keyRequest.algorithm = QVFLT_ALGO_AES_XTS_256;
        QvSendKeyToDriver(device, keyRequest);
    }

    HANDLE waitHandles[] = { g_StopEvent };
    WaitForMultipleObjects(1, waitHandles, FALSE, INFINITE);

    if (g_UsingDiskDriver) {
        DeviceIoControl(device, IOCTL_QVDISK_LOCK, nullptr, 0, nullptr, 0, nullptr, nullptr);
    } else {
        DeviceIoControl(device, IOCTL_QVFLT_LOCK, nullptr, 0, nullptr, 0, nullptr, nullptr);
    }

    CloseHandle(device);
    g_DeviceHandle = nullptr;
    g_UsingDiskDriver = FALSE;
    return NO_ERROR;
}

int wmain()
{
    SERVICE_TABLE_ENTRY serviceTable[] = {
        { const_cast<LPWSTR>(L"qvsvc"), QvServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcher(serviceTable)) {
        return static_cast<int>(GetLastError());
    }

    return 0;
}

#else
int main()
{
    return 0;
}
#endif

