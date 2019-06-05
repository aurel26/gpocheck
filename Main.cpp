/*
gpo2check
Copyright (c) 2019  aurel26

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include <Windows.h>
#define GLOBAL_DEFINE
#include "gpocheck.h"

#pragma comment(lib, "NetApi32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Ntdsapi.lib")

GENERIC_MAPPING g_FileMap2 =
{
   FILE_GENERIC_READ,
   FILE_GENERIC_WRITE,
   FILE_GENERIC_EXECUTE,
   FILE_ALL_ACCESS
};

int
wmain (
   int argc,
   wchar_t *argv[]
)
{
   BOOL bResult;

   HANDLE hLogonToken = NULL;
   HANDLE hStdOut;
   DWORD dwConsoleMode;
   DWORD dwSise;

   g_hHeap = HeapCreate(0, 0, 0);

   g_pSidAuthenticated = _HeapAlloc(SECURITY_MAX_SID_SIZE);
   g_pSidSystem = _HeapAlloc(SECURITY_MAX_SID_SIZE);
   g_pSidEDC = _HeapAlloc(SECURITY_MAX_SID_SIZE);
   g_pSidLocalAdministrators = _HeapAlloc(SECURITY_MAX_SID_SIZE);

   dwSise = SECURITY_MAX_SID_SIZE;
   CreateWellKnownSid(WinAuthenticatedUserSid, NULL, g_pSidAuthenticated, &dwSise);
   dwSise = SECURITY_MAX_SID_SIZE;
   CreateWellKnownSid(WinLocalSystemSid, NULL, g_pSidSystem, &dwSise);
   dwSise = SECURITY_MAX_SID_SIZE;
   CreateWellKnownSid(WinEnterpriseControllersSid, NULL, g_pSidEDC, &dwSise);
   dwSise = SECURITY_MAX_SID_SIZE;
   CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, g_pSidLocalAdministrators, &dwSise);

   //
   // Initialize console
   //
   hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

   // Set console output to 'ISO 8859-1 Latin 1; Western European (ISO)'
   SetConsoleOutputCP(28591);

   GetConsoleMode(hStdOut, &dwConsoleMode);
   g_bSupportsAnsi = SetConsoleMode(hStdOut, dwConsoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
   SetConsoleTitle(L"gpocheck");

   bResult = LdapGetRootDseInfo();
   if (bResult == FALSE)
      goto End;

   bResult = ConvertNcToDns();
   if (bResult == FALSE)
      goto End;

   bResult = LdapGetAllGpoObjects();
   if (bResult == FALSE)
      goto End;

End:
   _SafeHeapRelease(g_GlobalConfig.szDefaultNamingContext);
   _SafeHeapRelease(g_GlobalConfig.szDnsDomaineName);
   _SafeHeapRelease(g_GlobalConfig.szSysvolPrefix);

   _SafeHeapRelease(g_pSidLocalAdministrators);
   _SafeHeapRelease(g_pSidEDC);
   _SafeHeapRelease(g_pSidSystem);
   _SafeHeapRelease(g_pSidAuthenticated);

   HeapDestroy(g_hHeap);

   if (hLogonToken != NULL)
      CloseHandle(hLogonToken);
   if (g_GlobalConfig.hImpersonateToken != NULL)
      CloseHandle(g_GlobalConfig.hImpersonateToken);

   return EXIT_SUCCESS;
}