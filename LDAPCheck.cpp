#include <Windows.h>
#include <Winldap.h>
#include <Sddl.h>
#include <Aclapi.h>
#include <iads.h>
#include <stdio.h>
#include "gpocheck.h"

#define DS_GENERIC_READ ((STANDARD_RIGHTS_READ) | (ACTRL_DS_LIST) | (ACTRL_DS_READ_PROP) | (ACTRL_DS_LIST_OBJECT))
#define DS_GENERIC_EXECUTE ((STANDARD_RIGHTS_EXECUTE) | (ACTRL_DS_LIST))
#define DS_GENERIC_WRITE ((STANDARD_RIGHTS_WRITE) | (ACTRL_DS_SELF) | (ACTRL_DS_WRITE_PROP))
#define DS_GENERIC_ALL ((STANDARD_RIGHTS_REQUIRED) | (ACTRL_DS_CREATE_CHILD) | (ACTRL_DS_DELETE_CHILD) | (ACTRL_DS_DELETE_TREE) | (ACTRL_DS_READ_PROP) | (ACTRL_DS_WRITE_PROP) | (ACTRL_DS_LIST) | (ACTRL_DS_LIST_OBJECT) | (ACTRL_DS_CONTROL_ACCESS) | (ACTRL_DS_SELF))

GENERIC_MAPPING g_DsMap =
{
   DS_GENERIC_READ,
   DS_GENERIC_EXECUTE,
   DS_GENERIC_WRITE,
   DS_GENERIC_ALL
};

BOOL
pLdapGetSingleBinary(
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPCWSTR szAttributeName,
   _Outptr_opt_ PBYTE *pValue
);

BOOL
LdapCheckSd (
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPWSTR szGpoDn,
   _In_z_ LPWSTR szGpoCn,
   _In_opt_ PSID pSidOwnerGpo
)
{
   BOOL bResult;
   BOOL bSdValid = FALSE;
   LPWSTR szDn;

   PSECURITY_DESCRIPTOR pSd = NULL;
   PSID pSidOwner = NULL;
   BOOL bOwnerDefaulted;
   BOOL bPresent, bDefault;
   PACL pAcl;

   szDn = ldap_get_dn(pLdapHandle, pEntry);

   //
   // Bypass if we check GPO object
   //
   if (_wcsicmp(szGpoDn, szDn) == 0)
      goto End;

   bResult = pLdapGetSingleBinary(pLdapHandle, pEntry, L"nTSecurityDescriptor", (PBYTE*)&pSd);

   if (pSd == NULL)
      goto End;

   //
   // Check Security Descriptor
   //
   bResult = IsValidSecurityDescriptor(pSd);
   if (bResult == TRUE)
   {
      SECURITY_DESCRIPTOR_CONTROL SdControl;
      DWORD dwRevision;

      bSdValid = TRUE;

      bResult = GetSecurityDescriptorControl(pSd, &SdControl, &dwRevision);
      if (bResult == TRUE)
      {
         if (SdControl != (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED))
         {
            //
            // Control on LDAP sub object. Must be NOT SE_DACL_PROTECTED and SE_DACL_AUTO_INHERITED
            //
            if ((SdControl & SE_DACL_PROTECTED) == SE_DACL_PROTECTED)
               Log(
                  1, LOG_LEVEL_WARNING,
                  L"[x] %s'%s'%s %s\n      DACL is protected%s.",
                  COLOR_WHITE, szDn, COLOR_RESET,
                  COLOR_BRIGHT_RED, COLOR_RESET
               );

            if ((SdControl & SE_DACL_AUTO_INHERITED) == 0)
               Log(
                  1, LOG_LEVEL_WARNING,
                  L"[x] %s'%s'%s %s\n      DACL is not auto inherited%s.",
                  COLOR_WHITE, szDn, COLOR_RESET,
                  COLOR_BRIGHT_RED, COLOR_RESET
               );
         }
      }
      else
      {
         Log(
            0, LOG_LEVEL_ERROR,
            L"[!] %s'%s'%s %sGetSecurityDescriptorControl() failed%s (error %u).",
            COLOR_WHITE, szDn, COLOR_RESET,
            COLOR_RED, COLOR_RESET, GetLastError()
         );
      }

      bResult = GetSecurityDescriptorOwner(pSd, &pSidOwner, &bOwnerDefaulted);
      if (bResult == FALSE)
      {
         Log(
            0, LOG_LEVEL_ERROR,
            L"[!] %s'%s'%s %sGetSecurityDescriptorOwner() failed%s (error %u).",
            COLOR_WHITE, szDn, COLOR_RESET,
            COLOR_RED, COLOR_RESET, GetLastError()
         );
         pSidOwner = NULL;
      }
   }
   else
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[x] %s'%s'%s %sSecurity Descriptor is invalid%s.",
         COLOR_WHITE, szDn, COLOR_RESET,
         COLOR_RED, COLOR_RESET
      );
   }

   //
   // Check Owner
   //
   if ((pSidOwnerGpo!=NULL) && (pSidOwner != NULL))
   {
      //
      // Bypass owner check if owner is S-1-5-32-544 (BA)
      //
      bResult = EqualSid(pSidOwner, g_pSidLocalAdministrators);
      if (bResult == FALSE)
      {
         bResult = EqualSid(pSidOwner, pSidOwnerGpo);
         if (bResult == FALSE)
         {
            LPWSTR szSidOwnerGpo;
            LPWSTR szSidOwner;

            ConvertSidToStringSid(pSidOwnerGpo, &szSidOwnerGpo);
            ConvertSidToStringSid(pSidOwner, &szSidOwner);

            Log(
               1, LOG_LEVEL_WARNING,
               L"[x] %s'%s'%s %s\n      Owner SID (%s) is different from parent (%s)%s.",
               COLOR_WHITE, szDn, COLOR_RESET,
               COLOR_BRIGHT_RED, szSidOwner, szSidOwnerGpo, COLOR_RESET
            );

            LocalFree(szSidOwnerGpo);
            LocalFree(szSidOwner);
         }
      }
   }

   //
   // Check DACL
   //
   if (bSdValid == TRUE)
   {
      bResult = GetSecurityDescriptorDacl(pSd, &bPresent, &pAcl, &bDefault);
      if (bResult == TRUE)
      {
         if (pAcl == NULL)
         {
            Log(
               1, LOG_LEVEL_WARNING,
               L"[x] %s'%s'%s %s\n      has NULL DACL%s.",
               COLOR_WHITE, szDn, COLOR_RESET,
               COLOR_BRIGHT_RED, COLOR_RESET
            );
         }
         else if (pAcl->AceCount > 0)
         {
            LPWSTR szServerName;
            DWORD dwResult;
            PINHERITED_FROM pInheritedFrom = NULL;
            LPWSTR szGpoPath;
            size_t SizeGpoPath;
            LPWSTR szFullPath;
            size_t SizeFullPath;

            szServerName = g_GlobalConfig.szLdapServerName ? g_GlobalConfig.szLdapServerName : g_GlobalConfig.szDnsServerName;

            SizeGpoPath = 7 + wcslen(szServerName) + 1 + wcslen(szGpoDn) + 1;         // 7 'LDAP://', 1 '/', 1 NULL
            SizeFullPath = 7 + wcslen(szServerName) + 1 + wcslen(szDn) + 1;
            szGpoPath = (LPWSTR)_HeapAlloc(SizeGpoPath * sizeof(WCHAR));
            szFullPath = (LPWSTR)_HeapAlloc(SizeFullPath * sizeof(WCHAR));
            swprintf_s(szGpoPath, SizeGpoPath, L"LDAP://%s/%s", szServerName, szGpoDn);
            swprintf_s(szFullPath, SizeFullPath, L"LDAP://%s/%s", szServerName, szDn);

            pInheritedFrom = (PINHERITED_FROM)_HeapAlloc(sizeof(INHERITED_FROM) * pAcl->AceCount);
            if (pInheritedFrom == NULL)
               goto End;

            if (g_GlobalConfig.hImpersonateToken != NULL)
            {
               bResult = SetThreadToken(NULL, g_GlobalConfig.hImpersonateToken);
               if (bResult == FALSE)
               {
                  Log(
                     0, LOG_LEVEL_ERROR,
                     L"[x] %sSetThreadToken()failed%s (error %u).",
                     COLOR_RED, COLOR_RESET, GetLastError()
                  );
               }
               return FALSE;
            }

            dwResult = GetInheritanceSource(
               szFullPath,
               SE_DS_OBJECT_ALL,
               DACL_SECURITY_INFORMATION,
               TRUE,                            // Container
               NULL,
               0,
               pAcl,
               NULL,
               &g_DsMap,
               pInheritedFrom
            );

            if (g_GlobalConfig.hImpersonateToken != NULL)
               RevertToSelf();

            if (dwResult != ERROR_SUCCESS)
            {
               Log(
                  0, LOG_LEVEL_ERROR,
                  L"[!] %s'%s'%s %sGetInheritanceSource() failed%s (error %u).",
                  COLOR_WHITE, szDn, COLOR_RESET,
                  COLOR_RED, COLOR_RESET, GetLastError()
               );
            }
            else
            {
               for (DWORD i = 0; i < pAcl->AceCount; i++)
               {
                  PACE_HEADER pAce;
                  LPWSTR szSddl, szSddlAce;

                  if ((pInheritedFrom[i].AncestorName == NULL) || (pInheritedFrom[i].GenerationGap == -1))
                  {
                     bResult = GetAce(pAcl, i, (LPVOID*)&pAce);
                     szSddl = ConvertAceToSddl(pAce);

                     if (pAce->AceType == ACCESS_ALLOWED_ACE_TYPE)
                     {
                        PACCESS_ALLOWED_ACE pAceAllow;
                        PSID pSid;
                        PUCHAR pcSubAuthorityCount;

                        pAceAllow = (PACCESS_ALLOWED_ACE)pAce;
                        pSid = (PBYTE)&pAceAllow->SidStart;
                        pcSubAuthorityCount = GetSidSubAuthorityCount(pSid);

                        bResult = EqualSid(pSid, g_pSidSystem);
                        if (bResult == TRUE)
                           continue;
                        bResult = EqualSid(pSid, g_pSidEDC);
                        if ((bResult == TRUE) && (pAceAllow->Mask == 0x20094))         // 0x20094 = "Read"
                           continue;
                        bResult = EqualSid(pSid, g_pSidAuthenticated);
                        if ((bResult == TRUE) && (pAceAllow->Mask == 0x20094))         // 0x20094 = "Read"
                           continue;
                        if (*pcSubAuthorityCount == 5)
                        {
                           PDWORD pdwSubAuthority;

                           pdwSubAuthority = GetSidSubAuthority(pSid, 4);
                           if (*pdwSubAuthority == DOMAIN_GROUP_RID_ADMINS)
                              continue;
                        }
                     }

                     if (szSddl)
                     {
                        szSddlAce = wcschr(szSddl, 0x28);     // 0x28 -> '('
                        Log(
                           1, LOG_LEVEL_WARNING,
                           L"[x] %s'%s'%s %s\n      has unknown parent ACE%s %s.",
                           COLOR_WHITE, szDn, COLOR_RESET,
                           COLOR_BRIGHT_RED, COLOR_RESET, szSddlAce
                        );
                        LocalFree(szSddl);
                     }
                     else
                     {
                        Log(
                           1, LOG_LEVEL_WARNING,
                           L"[x] %s'%s'%s %s\n      has unknown parent ACE%s.",
                           COLOR_WHITE, szDn, COLOR_RESET,
                           COLOR_BRIGHT_RED, COLOR_RESET
                        );
                     }
                  }
                  else if (_wcsicmp(szGpoPath, pInheritedFrom[i].AncestorName) != 0)      // Different from root GPO directory
                  {
                     bResult = GetAce(pAcl, i, (LPVOID*)&pAce);
                     szSddl = ConvertAceToSddl(pAce);

                     if (szSddl)
                     {
                        szSddlAce = wcschr(szSddl, 0x28);     // 0x28 -> '('
                        Log(
                           1, LOG_LEVEL_WARNING,
                           L"[x] %s'%s'%s %s\n      has wrong parent ACE%s %s.",
                           COLOR_WHITE, szDn, COLOR_RESET,
                           COLOR_BRIGHT_RED, COLOR_RESET, szSddlAce
                        );
                        LocalFree(szSddl);
                     }
                     else
                     {
                        Log(
                           1, LOG_LEVEL_WARNING,
                           L"[x] %s'%s'%s %s\n      has wrong parent ACE%s.",
                           COLOR_WHITE, szDn, COLOR_RESET,
                           COLOR_BRIGHT_RED, COLOR_RESET
                        );
                     }
                  }
               }
            }

            FreeInheritedFromArray(pInheritedFrom, pAcl->AceCount, NULL);
            _SafeHeapRelease(pInheritedFrom);
            _SafeHeapRelease(szGpoPath);
            _SafeHeapRelease(szFullPath);
         }
      }
      else
      {
         Log(
            0, LOG_LEVEL_ERROR,
            L"[!] %s'%s'%s %sGetSecurityDescriptorDacl() failed%s (error %u).",
            COLOR_WHITE, szDn, COLOR_RESET,
            COLOR_RED, COLOR_RESET, GetLastError()
         );
      }
   }

End:
   _SafeHeapRelease(pSd);
   ldap_memfree(szDn);

   return TRUE;
}