// penguin injector c++.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// Includes
#include <iostream>
#include <Windows.h>
#include <iostream>
#include <string>
#include <ctype.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <Shlwapi.h>
#include <stdio.h>
#include "obfuscate.h"
#include <VersionHelpers.h>

// For Downloading
#pragma comment(lib, "urlmon.lib")
#define _CRT_SECURE_NO_WARNINGS // So I don't get get retarded warnings... I think it works ???

// STD Namespace
using namespace std; // STD Namespace so I don't have to include std:: before all std functions





// Get Process ID by its name Code copied from (my internet is offline right now so I'll add later on if I don't forget.)
//-----------------------------------------------------------
// Get Process ID by its name
//-----------------------------------------------------------
int getProcID(const string& p_name)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 structprocsnapshot = { 0 };

    structprocsnapshot.dwSize = sizeof(PROCESSENTRY32);

    if (snapshot == INVALID_HANDLE_VALUE)return 0;
    if (Process32First(snapshot, &structprocsnapshot) == FALSE)return 0;

    while (Process32Next(snapshot, &structprocsnapshot))
    {
        if (!strcmp(structprocsnapshot.szExeFile, p_name.c_str()))
        {
            CloseHandle(snapshot);
            cout << AY_OBFUSCATE("[+]Process name is: ") << p_name << AY_OBFUSCATE("\n[+]Process ID: ") << structprocsnapshot.th32ProcessID << endl;
            return structprocsnapshot.th32ProcessID;
        }
    }
    CloseHandle(snapshot);
    cerr << AY_OBFUSCATE("Unable to find Process ID") << endl;
    return 0;

}



// For Advanced Users
bool InjectDLL(const int& pid, const string& DLL_Path)
{
    long dll_size = DLL_Path.length() + 1;
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hProc == NULL)
    {
        cerr << AY_OBFUSCATE("[!]Fail to open target process!") << endl;
        return false;
    }
    cout << AY_OBFUSCATE("[+]Opening Target Process...") << endl;

    LPVOID MyAlloc = VirtualAllocEx(hProc, NULL, dll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (MyAlloc == NULL)
    {
        cerr << AY_OBFUSCATE("[!]Fail to allocate memory in Target Process.") << endl;
        return false;
    }

    cout << AY_OBFUSCATE("[+]Allocating memory in Target Process.") << endl;
    int IsWriteOK = WriteProcessMemory(hProc, MyAlloc, DLL_Path.c_str(), dll_size, 0);
    if (IsWriteOK == 0)
    {
        cerr << AY_OBFUSCATE("[!]Fail to write in Target Process memory.") << endl;
        return false;
    }
    cout << AY_OBFUSCATE("[+]Creating Remote Thread in Target Process") << endl;

    DWORD dWord;
    cout << "[+]Getting Kernel Access For Load Library" << endl;
    LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary(AY_OBFUSCATE("kernel32")), AY_OBFUSCATE("LoadLibraryA"));
    HANDLE ThreadReturn = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, MyAlloc, 0, &dWord);
    if (ThreadReturn == NULL)
    {
        cerr << AY_OBFUSCATE("[!]Fail to create Remote Thread") << endl;
        return false;
    }

    if ((hProc != NULL) && (MyAlloc != NULL) && (IsWriteOK != ERROR_INVALID_HANDLE) && (ThreadReturn != NULL))
    {
        cout << AY_OBFUSCATE("[+]DLL Successfully Injected :p") << endl;
        return true;
    }

    return false;
}




void cls() // Void function for cls so I can just do cls(); instead of system("cls"); Yes I understand this is unsafe and I'm pretty sure I could've used flush but I'm lazy.
{
    system(AY_OBFUSCATE("cls")); // Clear screen with system using the include <Windows.h>
}

void welcome() // Function I can call for the welcome screen. Note: All AY_OBFUSCATE are so debuggers cannot find the string included in the cout... You can remove this if you want and to clear space also remove obfuscate.h while your at it.
{
    cout << AY_OBFUSCATE("/");
    Sleep(200); // Sleep for 2/10 of a second
    cls();
    cout << AY_OBFUSCATE("");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("W");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("W3");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("W");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WE");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WE7");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WE");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WEL");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WEL5");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WEL");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELC");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELC0");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELC0\\");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELC0\\/");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELC0\\");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELC0");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELC");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCO");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOM/");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOM");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOM3");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOM");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME ");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME >");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME >>");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME >>>");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME >>>>");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME B>>>");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME BA>>");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME BAC>");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME BACK");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME BACK ");
    Sleep(200);
    cls();
    cout << AY_OBFUSCATE("WELCOME BACK ") << getenv(AY_OBFUSCATE("USERNAME")); // The get enviroment function just gets the username of the person opening the application...
    Sleep(2000); // Sleep obviously just makes the application sleep for the specified amount of miliseconds.

}

BOOL IsElevated() { // Check if admin
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

double getWinVerion() { // Get windows version

    OSVERSIONINFO info;
    ZeroMemory(&info, sizeof(OSVERSIONINFO));
    info.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    GetVersionEx(&info);

    std::string version = std::to_string(info.dwMajorVersion);
    version.append(".").append(std::to_string(info.dwMinorVersion));

    if (IsWindows7SP1OrGreater()) {
        if (version == "6.1")
            return 6.1;
    }

    if (IsWindows8Point1OrGreater())
        return 6.3;
    else
        return 10.0;
}

int main()
{

    // Checking if it's being ran as admin.
    if (!IsElevated())
    {
        cout << "Please run me as admin! Otherwise I cannot inject any dlls.";
        Sleep(2000);
        exit(500);
    }


    // Check windows version and reject if less than v10

    if (getWinVerion() != 10)
    {
        cout << "Oops! We only support windows 10 at the moment..." << endl;
        cout << "Detected Windows Version: " << getWinVerion() << endl;
        Sleep(4000);
        exit(500);
    } 



    string pName; // Set process name string
    string dllPath; // Set dllPath string
    welcome(); // Call the welcome function.
    cls(); // Unsafe yes I know.
    cout << AY_OBFUSCATE("Application Name (Please Include The .exe): "); // What it says retard
    cin >> pName; // if you don't know what this is then... just... learn c plus plus

    cout << AY_OBFUSCATE("DLL Path: "); // Duh
    cin >> dllPath; // Obv
    if (InjectDLL(getProcID(pName), dllPath))
    {
        cout << "[+] Enjoy!" << endl;
        Sleep(5000);
        exit(500);
    }
    else {
        cout << "[-]Something went terribly wrong!" << endl;
        Sleep(5000);
        exit(500);
    }// Inject using int and dllPath
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
