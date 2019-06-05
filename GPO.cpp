#include <Windows.h>
#include <Winldap.h>
#include <stdio.h>
#include "gpocheck.h"

BOOL
pLdapGetSingleInteger(
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPCWSTR szAttributeName,
   _Outptr_opt_ LPDWORD pdwValue
);

BOOL
pLdapGetSingleString(
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPCWSTR szAttributeName,
   _Outptr_opt_ LPWSTR *pszValue
);

BOOL
pLdapGetSingleBinary(
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPCWSTR szAttributeName,
   _Outptr_opt_ PBYTE *pValue
);

BOOL
LdapGetAllChildrenAndCheckSd(
   _In_ LDAP *pLdapHandle,
   _In_z_ LPWSTR szDn,
   _In_z_ LPWSTR szCn,
   _In_opt_ PSID pSidOwnerGpo
);

BOOL
GpoCheck (
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry
)
{
   BOOL bResult;
   LPWSTR szDn;
   size_t SizeSysvolPath;

   DWORD dwFunctionalityVersion;
   DWORD dwFlags;
   DWORD dwVersionNumber;

   LPWSTR szCn = NULL;
   LPWSTR szMachineExtensionNames = NULL;
   LPWSTR szUserExtensionNames = NULL;
   LPWSTR szFileSysPath = NULL;
   LPWSTR szFileSysPathComputed;
   LPWSTR szDisplayName = NULL;

   PSECURITY_DESCRIPTOR pSd = NULL;
   PSID pSidOwnerGpo = NULL;
   BOOL bOwnerDefaulted;

   szDn = ldap_get_dn(pLdapHandle, pEntry);

   bResult = pLdapGetSingleString(pLdapHandle, pEntry, L"displayName", &szDisplayName);
   bResult = pLdapGetSingleString(pLdapHandle, pEntry, L"cn", &szCn);

   Log(
      0, LOG_LEVEL_INFORMATION,
      L"[.] %sCheck '%s'%s (%s).",
      COLOR_CYAN, szCn, COLOR_RESET, szDisplayName
   );

   bResult = pLdapGetSingleInteger(pLdapHandle, pEntry, L"gPCFunctionalityVersion", &dwFunctionalityVersion);
   bResult = pLdapGetSingleInteger(pLdapHandle, pEntry, L"flags", &dwFlags);
   bResult = pLdapGetSingleInteger(pLdapHandle, pEntry, L"versionNumber", &dwVersionNumber);

   bResult = pLdapGetSingleString(pLdapHandle, pEntry, L"gPCMachineExtensionNames", &szMachineExtensionNames);
   bResult = pLdapGetSingleString(pLdapHandle, pEntry, L"gPCUserExtensionNames", &szUserExtensionNames);
   bResult = pLdapGetSingleString(pLdapHandle, pEntry, L"gPCFileSysPath", &szFileSysPath);

   bResult = pLdapGetSingleBinary(pLdapHandle, pEntry, L"nTSecurityDescriptor", (PBYTE*)&pSd);

   SizeSysvolPath = wcslen(g_GlobalConfig.szSysvolPrefix) + 39;
   szFileSysPathComputed = (LPWSTR)_HeapAlloc(SizeSysvolPath * sizeof(WCHAR));
   swprintf_s(szFileSysPathComputed, SizeSysvolPath, L"%s%s", g_GlobalConfig.szSysvolPrefix, szCn);

   //
   // Check gPCFunctionalityVersion
   //
   if (dwFunctionalityVersion != 2)
   {
      Log(
         1, LOG_LEVEL_WARNING,
         L"[x] %s'%s' (%s)%s %s\n      Wrong funtionality level%s (gPCFunctionalityVersion = %u).",
         COLOR_WHITE, szCn, szDisplayName, COLOR_RESET,
         COLOR_BRIGHT_RED, COLOR_RESET, dwFunctionalityVersion
      );
   }

   //
   // Check Disable
   //
   if ((dwVersionNumber & 0x0000ffff) == 0)
   {
      // Computer empty
      if ((dwFlags & 2) == 0)            // 2: computer configuration portion of GPO is disabled
      {
         Log(
            1, LOG_LEVEL_WARNING,
            L"[x] %s'%s' (%s)%s %s\n      Computer part empty but not disabled%s.",
            COLOR_WHITE, szCn, szDisplayName, COLOR_RESET,
            COLOR_YELLOW, COLOR_RESET
         );
      }
   }

   if ((dwVersionNumber & 0xffff0000) == 0)
   {
      // User empty
      if ((dwFlags & 1) == 0)            // 1: user configuration portion of the GPO is disabled
      {
         Log(
            1, LOG_LEVEL_WARNING,
            L"[x] %s'%s' (%s)%s %s\n      User part empty but not disabled%s.",
            COLOR_WHITE, szCn, szDisplayName, COLOR_RESET,
            COLOR_YELLOW, COLOR_RESET
         );
      }
   }

   //
   // Check Security Descriptor
   //
   bResult = IsValidSecurityDescriptor(pSd);
   if (bResult == TRUE)
   {
      SECURITY_DESCRIPTOR_CONTROL SdControl;
      DWORD dwRevision;

      bResult = GetSecurityDescriptorControl(pSd, &SdControl, &dwRevision);
      if (bResult == TRUE)
      {
         if (SdControl != (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED ))
         {
            //
            // Control on LDAP GPO object. Must be SE_DACL_PROTECTED and SE_DACL_AUTO_INHERITED
            //
            if ((SdControl & SE_DACL_PROTECTED) == 0)
               Log(
                  1, LOG_LEVEL_WARNING,
                  L"[x] %s'%s' (%s)%s %s\n      DACL is not protected%s.",
                  COLOR_WHITE, szCn, szDisplayName, COLOR_RESET,
                  COLOR_BRIGHT_RED, COLOR_RESET
               );

            if ((SdControl & SE_DACL_AUTO_INHERITED) == 0)
               Log(
                  1, LOG_LEVEL_WARNING,
                  L"[x] %s'%s' (%s)%s %s\n      DACL is not auto inherited%s.",
                  COLOR_WHITE, szCn, szDisplayName, COLOR_RESET,
                  COLOR_BRIGHT_RED, COLOR_RESET
               );
         }
      }
      else
      {
         Log(
            0, LOG_LEVEL_ERROR,
            L"[!] %s'%s' (%s)%s %sGetSecurityDescriptorControl() failed%s (error %u).",
            COLOR_WHITE, szCn, szDisplayName, COLOR_RESET,
            COLOR_RED, COLOR_RESET, GetLastError()
         );
      }

      bResult = GetSecurityDescriptorOwner(pSd, &pSidOwnerGpo, &bOwnerDefaulted);
      if (bResult == FALSE)
      {
         Log(
            0, LOG_LEVEL_ERROR,
            L"[!] %s'%s' (%s)%s %sGetSecurityDescriptorOwner() failed%s (error %u).",
            COLOR_WHITE, szCn, szDisplayName, COLOR_RESET,
            COLOR_RED, COLOR_RESET, GetLastError()
         );
         pSidOwnerGpo = NULL;
      }
   }
   else
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[x] %s'%s' (%s)%s %sSecurity Descriptor is invalid.%s",
         COLOR_WHITE, szCn, szDisplayName, COLOR_RESET,
         COLOR_RED, COLOR_RESET
      );
   }

   //
   // Check LDAP children objects
   //
   LdapGetAllChildrenAndCheckSd(pLdapHandle, szDn, szCn, pSidOwnerGpo);

   //
   // Check gPCFileSysPath
   //
   if (_wcsicmp(szFileSysPath, szFileSysPathComputed) != 0)
   {
      Log(
         1, LOG_LEVEL_WARNING,
         L"[x] %s'%s' (%s)%s %s\n      Incorrect SYSVOL Path%s (gPCFileSysPath = '%s').",
         COLOR_WHITE, szCn, szDisplayName, COLOR_RESET,
         COLOR_BRIGHT_RED, COLOR_RESET, szFileSysPath
      );
   }

   //
   // Check Sysvol permissions
   //
   FolderProcessGpo(szFileSysPath, szCn, szDisplayName);

   _SafeHeapRelease(szFileSysPathComputed);

   _SafeHeapRelease(szCn);
   _SafeHeapRelease(szMachineExtensionNames);
   _SafeHeapRelease(szUserExtensionNames);
   _SafeHeapRelease(szFileSysPath);
   _SafeHeapRelease(szDisplayName);
   _SafeHeapRelease(pSd);

   ldap_memfree(szDn);

   return TRUE;
}

//
// Private functions
//
BOOL
pLdapGetSingleInteger (
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPCWSTR szAttributeName,
   _Outptr_opt_ LPDWORD pdwValue
)
{
   BOOL bReturn = TRUE;
   LPWSTR *ppValue = NULL;

   ppValue = ldap_get_values(pLdapHandle, pEntry, (LPWSTR)szAttributeName);

   if (ppValue != NULL)
   {
      int r;

      r = swscanf_s(ppValue[0], L"%u", pdwValue);
      if (r != 1)
         bReturn = FALSE;

         ldap_value_free(ppValue);
   }
   else
   {
      ULONG ulLastLdapError;

      ulLastLdapError = LdapGetLastError();

      Log(
         0, LOG_LEVEL_VERYVERBOSE,
         L"[x] %sUnable to read LDAP integer '%s' attribute%s (error %u: %s).",
         COLOR_RED, szAttributeName, COLOR_RESET, ulLastLdapError, ldap_err2string(ulLastLdapError)
      );
      bReturn = FALSE;
   }

   return bReturn;
}

BOOL
pLdapGetSingleString (
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPCWSTR szAttributeName,
   _Outptr_opt_ LPWSTR *pszValue
)
{
   BOOL bReturn = TRUE;
   LPWSTR *ppValue = NULL;

   ppValue = ldap_get_values(pLdapHandle, pEntry, (LPWSTR)szAttributeName);

   if (ppValue != NULL)
   {
      StringDuplicate(ppValue[0], pszValue);
      ldap_value_free(ppValue);
   }
   else
   {
      ULONG ulLastLdapError;

      ulLastLdapError = LdapGetLastError();

      Log(
         0, LOG_LEVEL_VERYVERBOSE,
         L"[x] %sUnable to read LDAP string '%s' attribute%s (error %u: %s).",
         COLOR_RED, szAttributeName, COLOR_RESET, ulLastLdapError, ldap_err2string(ulLastLdapError)
      );
      bReturn = FALSE;
   }

   return bReturn;
}

BOOL
pLdapGetSingleBinary (
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPCWSTR szAttributeName,
   _Outptr_opt_ PBYTE *pValue
)
{
   BOOL bReturn = TRUE;
   berval **ppval = NULL;

   ppval = ldap_get_values_len(pLdapHandle, pEntry, (LPWSTR)szAttributeName);

   if (ppval != NULL)
   {
      *pValue = (PBYTE)_HeapAlloc(ppval[0]->bv_len);
      memcpy(*pValue, ppval[0]->bv_val, ppval[0]->bv_len);
      ldap_value_free_len(ppval);
   }
   else
   {
      ULONG ulLastLdapError;

      ulLastLdapError = LdapGetLastError();

      Log(
         0, LOG_LEVEL_ERROR,
         L"[x] %sUnable to read LDAP binary '%s' attribute%s (error %u: %s).",
         COLOR_RED, szAttributeName, COLOR_RESET, ulLastLdapError, ldap_err2string(ulLastLdapError)
      );
      bReturn = FALSE;
   }

   return bReturn;
}