// TSK714A_System_Drive_Encryption_(PreBoot_Windows_First)_Stage1_Minifilter

#ifdef _WIN32
#include <Windows.h>
#include "../../include/qv/platform/win/qvflt_ioctl.h"

#pragma comment(lib, "Advapi32.lib")

static SERVICE_STATUS_HANDLE g_ServiceStatusHandle = nullptr;
static HANDLE g_StopEvent = nullptr;
static const wchar_t kDevicePath[] = L"\\\\.\\QvFlt";

static VOID WINAPI QvServiceMain(DWORD argc, LPWSTR *argv);
static VOID WINAPI QvServiceCtrlHandler(DWORD control);
static DWORD WINAPI QvServiceWorker(LPVOID context);

static BOOL QvSendKeyToDriver(HANDLE device, const QVFLT_KEY_REQUEST &request)
{
    DWORD bytesReturned = 0;
    return DeviceIoControl(device, IOCTL_QVFLT_SET_KEY, (LPVOID)&request, sizeof(request), nullptr, 0, &bytesReturned, nullptr);
}

static VOID ReportServiceStatus(DWORD currentState, DWORD exitCode)
{
    SERVICE_STATUS status = {};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_POWEREVENT;
    status.dwCurrentState = currentState;
    status.dwWin32ExitCode = exitCode;
    SetServiceStatus(g_ServiceStatusHandle, &status);
}

static VOID WINAPI QvServiceCtrlHandler(DWORD control)
{
    if (control == SERVICE_CONTROL_STOP) {
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR);
        if (g_StopEvent != nullptr) {
            SetEvent(g_StopEvent);
        }
    }
}

static VOID WINAPI QvServiceMain(DWORD argc, LPWSTR *argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_ServiceStatusHandle = RegisterServiceCtrlHandler(L"qvsvc", QvServiceCtrlHandler);
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

    HANDLE device = CreateFile(kDevicePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    QVFLT_KEY_REQUEST keyRequest = {};
    keyRequest.algorithm = QVFLT_ALGO_AES_XTS_256;

    QvSendKeyToDriver(device, keyRequest);

    HANDLE waitHandles[] = { g_StopEvent };
    WaitForMultipleObjects(1, waitHandles, FALSE, INFINITE);

    DeviceIoControl(device, IOCTL_QVFLT_LOCK, nullptr, 0, nullptr, 0, nullptr, nullptr);
    CloseHandle(device);
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

