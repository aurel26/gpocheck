#include <Windows.h>
#include <ntdsapi.h>
#include <sddl.h>
#include <stdio.h>
#include "gpocheck.h"

#define MSG_MAX_SIZE       8192

VOID
Log (
   _In_ DWORD dwIndent,
   _In_ DWORD dwLevel,
   _In_z_ LPCWSTR szFormat,
   ...
)
{
   int r;

   WCHAR szMessage[MSG_MAX_SIZE];
   SYSTEMTIME st;

   va_list argptr;
   va_start(argptr, szFormat);

   GetLocalTime(&st);

   r = vswprintf_s(szMessage, MSG_MAX_SIZE, szFormat, argptr);
   if (r == -1)
   {
      return;
   }

   for (DWORD i = 0; i < dwIndent; i++)
   {
      wprintf(L"  ");
   }

   if (dwLevel <= LOG_LEVEL_INFORMATION)
      wprintf(L"%s\n", szMessage);

   /*
   if (dwLevel <= LOG_LEVEL_VERBOSE)
   {
      DWORD dwDataSize, dwDataWritten;
      WCHAR szLine[INFO_MAX_SIZE];

      swprintf_s(
         szLine, INFO_MAX_SIZE,
         L"%04u/%02u/%02u - %02u:%02u:%02u.%03u\t%s\r\n",
         st.wYear, st.wMonth, st.wDay,
         st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
         szMessage
      );

      dwDataSize = (DWORD)wcsnlen_s(szLine, INFO_MAX_SIZE);
      WriteFile(g_hLogFile, szLine, dwDataSize * sizeof(WCHAR), &dwDataWritten, NULL);
   }
   */
}

VOID
StringDuplicate (
   _In_z_ LPWSTR szInput,
   _Out_ LPWSTR *szOutput
)
{
   size_t InputSize;

   if ((szInput == NULL) || (szOutput == NULL))
      return;

   InputSize = wcslen(szInput);
   *szOutput = (LPWSTR)_HeapAlloc((InputSize + 1) * sizeof(WCHAR));
   if (*szOutput == NULL)
      return;

   memcpy(*szOutput, szInput, InputSize * sizeof(WCHAR));
}

BOOL
ConvertNcToDns (
)
{
   DWORD dwResult;

   PDS_NAME_RESULT pResult;

   dwResult = DsCrackNames(
      NULL,
      DS_NAME_FLAG_SYNTACTICAL_ONLY,
      DS_FQDN_1779_NAME,
      DS_CANONICAL_NAME,
      1,
      &g_GlobalConfig.szDefaultNamingContext,
      &pResult
   );

   if (dwResult == ERROR_SUCCESS)
   {
      size_t SizeDomaineName;

      StringDuplicate(pResult->rItems[0].pDomain, &g_GlobalConfig.szDnsDomaineName);
      DsFreeNameResult(pResult);

      SizeDomaineName = 2 * wcslen(g_GlobalConfig.szDnsDomaineName) + 21;
      g_GlobalConfig.szSysvolPrefix = (LPWSTR)_HeapAlloc(SizeDomaineName * sizeof(WCHAR));
      if (g_GlobalConfig.szSysvolPrefix == NULL)
         return FALSE;
      swprintf_s(g_GlobalConfig.szSysvolPrefix, SizeDomaineName, L"\\\\%s\\SysVol\\%s\\Policies\\", g_GlobalConfig.szDnsDomaineName, g_GlobalConfig.szDnsDomaineName);
   }
   else
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sDsCrackNames() failed%s (error %u).",
         COLOR_RED, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }

   return TRUE;
}

LPWSTR
ConvertAceToSddl (
   _In_ PACE_HEADER pACE
)
{
   BOOL bResult;
   LPWSTR szSddl;

   DWORD dwSize;

   PACL pAcl;
   SECURITY_DESCRIPTOR Sd = { 0 };

   dwSize = sizeof(ACL) + (1 * sizeof(ACCESS_ALLOWED_ACE)) + SECURITY_MAX_SID_SIZE;

   pAcl = (PACL)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwSize);
   if (pAcl == FALSE)
      return NULL;

   bResult = InitializeAcl(pAcl, dwSize, ACL_REVISION);
   if (bResult == FALSE)
      return NULL;

   if ((pACE->AceType == ACCESS_ALLOWED_ACE_TYPE) || (pACE->AceType == ACCESS_DENIED_ACE_TYPE))
   {
      bResult = AddAce(pAcl, ACL_REVISION, MAXDWORD, pACE, ((PACE_HEADER)pACE)->AceSize);
      if (bResult == FALSE)
         return NULL;
   }
   else if ((pACE->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE) || (pACE->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE))
   {
      bResult = AddAce(pAcl, ACL_REVISION_DS, MAXDWORD, pACE, ((PACE_HEADER)pACE)->AceSize);
      if (bResult == FALSE)
         return NULL;
   }
   else
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sUnknown ACE type%s (%u).",
         COLOR_RED, COLOR_RESET, pACE->AceType
      );
      return NULL;
   }

   bResult = InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
   if (bResult == FALSE)
      return NULL;

   bResult = SetSecurityDescriptorDacl(&Sd, TRUE, pAcl, FALSE);
   if (bResult == FALSE)
      return NULL;

   bResult = ConvertSecurityDescriptorToStringSecurityDescriptor(
      &Sd,
      SDDL_REVISION_1,
      DACL_SECURITY_INFORMATION,
      &szSddl,
      NULL
   );

   _SafeHeapRelease(pAcl);

   if (bResult == TRUE)
      return szSddl;
   else
      return NULL;
}
