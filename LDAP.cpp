#include <Windows.h>
#include <Winldap.h>
#include <Winber.h>
#include <NtLdap.h>           // For LDAP Extended Controls
#include <stdio.h>
#include <Intsafe.h>
#include "gpocheck.h"

//
// GPO.CPP
//
BOOL
GpoCheck(
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry
);

//
// LDAPCheck.cpp
//
BOOL
LdapCheckSd(
   _In_ LDAP *pLdapHandle,
   _In_ LDAPMessage *pEntry,
   _In_z_ LPWSTR szGpoDn,
   _In_z_ LPWSTR szGpoCn,
   _In_opt_ PSID pSidOwnerGpo
);

//
// Private functions definition
//
LDAP*
pLdapOpenConnection(
);

//
// Public functions
//
BOOL
LdapGetRootDseInfo (
)
{
   ULONG ulResult;

   LDAP* pLdapHandle;
   LDAPMessage *pLdapMessage = NULL;
   LDAPMessage *pEntry = NULL;
   PWCHAR pAttribute = NULL;
   BerElement* pBer = NULL;

   LPCWSTR szAttrsSearch[] = {
      L"dnsHostName",
      L"defaultNamingContext",
      NULL
   };

   pLdapHandle = pLdapOpenConnection();
   if (pLdapHandle == NULL)
      return FALSE;

   ulResult = ldap_search_s(pLdapHandle, NULL, LDAP_SCOPE_BASE, NULL, (PZPWSTR)szAttrsSearch, FALSE, &pLdapMessage);
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sError in ldap_search_s()%s (error %u: %s).", COLOR_RED, COLOR_RESET, ulResult, ldap_err2string(ulResult)
      );
      return FALSE;
   }

   pEntry = ldap_first_entry(pLdapHandle, pLdapMessage);
   pAttribute = ldap_first_attribute(pLdapHandle, pEntry, &pBer);

   while (pAttribute != NULL)
   {
      PWCHAR *ppValue = NULL;

      ppValue = ldap_get_values(pLdapHandle, pEntry, pAttribute);

      if (ppValue != NULL)
      {
         if ((wcscmp(pAttribute, L"dnsHostName") == 0) && (wcslen(pAttribute) > 0))
            StringDuplicate(ppValue[0], &g_GlobalConfig.szDnsServerName);
         if ((wcscmp(pAttribute, L"defaultNamingContext") == 0) && (wcslen(pAttribute) > 0))
            StringDuplicate(ppValue[0], &g_GlobalConfig.szDefaultNamingContext);
      }

      ldap_memfree(pAttribute);
      pAttribute = ldap_next_attribute(pLdapHandle, pEntry, pBer);
   }

   if (pBer != NULL)
   {
      ber_free(pBer, 0);
      pBer = NULL;
   }

   ulResult = ldap_msgfree(pLdapMessage);
   ulResult = ldap_unbind(pLdapHandle);

   return TRUE;
}

BOOL
LdapGetAllGpoObjects (
)
{
   ULONG ulResult;
   ULONG ulEntriesCount;
   ULONG ulReturnCode;

   LDAP *pLdapHandle;
   LDAPMessage *pLdapMessage = NULL;
   LDAPMessage *pEntry = NULL;

   PLDAPControl pLdapControl = NULL;
   PLDAPControl serverControlArray[3] = { 0 };     // 0: paging, 1:LDAP_SERVER_SD_FLAGS_OID, 2: NULL
   LDAP_BERVAL LdapCookie = { 0, NULL };
   LDAPControl LdapControlSdFlag;
   BerElement *pBerElmt = NULL;
   berval *pBerVal = NULL;

   PLDAP_BERVAL pLdapNewCookie = NULL;
   PLDAPControl *currControls = NULL;

   LPCWSTR szAttrsSearch[] = {
      L"cn",
      L"flags",
      L"versionNumber",
      L"gPCFileSysPath",
      L"gPCFunctionalityVersion",
      L"gPCMachineExtensionNames",
      L"gPCUserExtensionNames",
      L"nTSecurityDescriptor",
      L"displayName",
      NULL
   };

   //
   // Open connection
   //
   pLdapHandle = pLdapOpenConnection();
   if (pLdapHandle == NULL)
      return FALSE;

   //
   // Prepare server controls
   //
   ulResult = ldap_create_page_control(
      pLdapHandle,
      900,
      &LdapCookie,
      TRUE,                // IsCritical
      &pLdapControl
   );

   pBerElmt = ber_alloc_t(LBER_USE_DER);
   ber_printf(pBerElmt, (PSTR)"{i}", (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION));
   ber_flatten(pBerElmt, &pBerVal);
   ber_free(pBerElmt, 1);

   LdapControlSdFlag.ldctl_iscritical = TRUE;
   LdapControlSdFlag.ldctl_oid = (LPWSTR)LDAP_SERVER_SD_FLAGS_OID_W;
   LdapControlSdFlag.ldctl_value.bv_val = pBerVal->bv_val;
   LdapControlSdFlag.ldctl_value.bv_len = pBerVal->bv_len;

   serverControlArray[0] = pLdapControl;
   serverControlArray[1] = &LdapControlSdFlag;

   //
   // Request
   //
Search:
   ulResult = ldap_search_ext_s(
      pLdapHandle,
      g_GlobalConfig.szDefaultNamingContext,
      LDAP_SCOPE_SUBTREE,
      (LPWSTR)L"(objectClass=groupPolicyContainer)",
      (PZPWSTR)szAttrsSearch,
      FALSE,               // attrsonly
      serverControlArray,  // ServerControls
      NULL,                // ClientControls
      0,                   // timeout
      0,                   // SizeLimit
      &pLdapMessage
   );
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sError in ldap_search_ext_s()%s (error %u: %s).",
         COLOR_RED, COLOR_RESET, ulResult, ldap_err2string(ulResult)
      );
      return FALSE;
   }

   ulEntriesCount = ldap_count_entries(
      pLdapHandle,
      pLdapMessage
   );

   for (ULONG i = 0; i < ulEntriesCount; i++)
   {
      if (i == 0)
         pEntry = ldap_first_entry(pLdapHandle, pLdapMessage);
      else
         pEntry = ldap_next_entry(pLdapHandle, pEntry);

      GpoCheck(pLdapHandle, pEntry);
   }

   ulResult = ldap_parse_result(
      pLdapHandle,
      pLdapMessage,
      &ulReturnCode,
      NULL,
      NULL,
      NULL,
      &currControls,
      FALSE
   );
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sError in ldap_parse_result()%s (error %u: %s).",
         COLOR_RED, COLOR_RESET, ulResult, ldap_err2string(ulResult)
      );
      return FALSE;
   }

   ulResult = ldap_parse_page_control(pLdapHandle, currControls, NULL, (berval**)&pLdapNewCookie);
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sError in ldap_parse_page_control()%s (error %u: %s).",
         COLOR_RED, COLOR_RESET, ulResult, ldap_err2string(ulResult)
      );
      return FALSE;
   }

   if ((pLdapNewCookie->bv_len == 0) || (pLdapNewCookie->bv_val == 0))
      return FALSE;

   serverControlArray[0] = NULL;

   ulResult = ldap_create_page_control(
      pLdapHandle,
      900,
      pLdapNewCookie,
      TRUE,
      &serverControlArray[0]
   );
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sError in ldap_create_page_control()%s (error %u: %s).",
         COLOR_RED, COLOR_RESET, ulResult, ldap_err2string(ulResult)
      );
      return FALSE;
   }

   ldap_msgfree(pLdapMessage);

   goto Search;

   ber_bvfree(pBerVal);
   ulResult = ldap_control_free(pLdapControl);
   ulResult = ldap_msgfree(pLdapMessage);
   ulResult = ldap_unbind(pLdapHandle);

   return TRUE;
}

BOOL
LdapGetAllChildrenAndCheckSd (
   _In_ LDAP *pLdapHandle,
   _In_z_ LPWSTR szDn,
   _In_z_ LPWSTR szCn,
   _In_opt_ PSID pSidOwnerGpo
)
{
   ULONG ulResult;
   ULONG ulEntriesCount;

   LDAPMessage *pLdapMessage = NULL;
   LDAPMessage *pEntry = NULL;

   PLDAPControl serverControlArray[2] = { 0 };     // 0:LDAP_SERVER_SD_FLAGS_OID, 1: NULL
   LDAPControl LdapControlSdFlag;
   BerElement *pBerElmt = NULL;
   berval *pBerVal = NULL;

   LPCWSTR szAttrsSearch[] = {
      L"nTSecurityDescriptor",
      NULL
   };

   //
   // Prepare server controls
   //
   pBerElmt = ber_alloc_t(LBER_USE_DER);
   ber_printf(pBerElmt, (PSTR)"{i}", (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION));
   ber_flatten(pBerElmt, &pBerVal);
   ber_free(pBerElmt, 1);

   LdapControlSdFlag.ldctl_iscritical = TRUE;
   LdapControlSdFlag.ldctl_oid = (LPWSTR)LDAP_SERVER_SD_FLAGS_OID_W;
   LdapControlSdFlag.ldctl_value.bv_val = pBerVal->bv_val;
   LdapControlSdFlag.ldctl_value.bv_len = pBerVal->bv_len;

   serverControlArray[0] = &LdapControlSdFlag;

   //
   // Request
   //
   ulResult = ldap_search_ext_s(
      pLdapHandle,
      szDn,
      LDAP_SCOPE_SUBTREE,
      (LPWSTR)L"(objectClass=*)",
      (PZPWSTR)szAttrsSearch,
      FALSE,               // attrsonly
      serverControlArray,  // ServerControls
      NULL,                // ClientControls
      0,                   // timeout
      0,                   // SizeLimit
      &pLdapMessage
   );
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sError in ldap_search_ext_s()%s (error %u: %s).", COLOR_RED, COLOR_RESET, ulResult, ldap_err2string(ulResult)
      );
      return FALSE;
   }

   ulEntriesCount = ldap_count_entries(
      pLdapHandle,
      pLdapMessage
   );

   for (ULONG i = 0; i < ulEntriesCount; i++)
   {
      if (i == 0)
         pEntry = ldap_first_entry(pLdapHandle, pLdapMessage);
      else
         pEntry = ldap_next_entry(pLdapHandle, pEntry);

      LdapCheckSd(pLdapHandle, pEntry, szDn, szCn, pSidOwnerGpo);
   }

   ulResult = ldap_msgfree(pLdapMessage);

   return TRUE;
}

//
// Private functions
//
LDAP*
pLdapOpenConnection (
)
{
   ULONG ulResult;
   ULONG ulVersion;
   void *pvValue = NULL;

   LDAP* pLdapHandle = NULL;

   pLdapHandle = ldap_open(
      g_GlobalConfig.szLdapServerName,
      (g_GlobalConfig.dwLdapServerPort) ? g_GlobalConfig.dwLdapServerPort : LDAP_PORT
   );

   if (pLdapHandle == NULL)
   {
      ulResult = LdapGetLastError();
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sUnable to open LDAP connection to %s%s (error %u: %s).",
         COLOR_RED, g_GlobalConfig.szLdapServerName, COLOR_RESET, ulResult, ldap_err2string(ulResult)
      );
      return NULL;
   }

   ulResult = ldap_connect(pLdapHandle, NULL);
   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sUnable to connect to LDAP server%s (error %u: %s).", COLOR_RED, COLOR_RESET, ulResult, ldap_err2string(ulResult)
      );
      ldap_unbind(pLdapHandle);
      return NULL;
   }

   ulVersion = LDAP_VERSION3;
   ulResult = ldap_set_option(pLdapHandle, LDAP_OPT_PROTOCOL_VERSION, (void*)&ulVersion);
   pvValue = LDAP_OPT_OFF;
   ulResult = ldap_set_option(pLdapHandle, LDAP_OPT_REFERRALS, &pvValue);

   if (g_GlobalConfig.szUsername == NULL)
   {
      ulResult = ldap_bind_s(pLdapHandle, NULL, NULL, LDAP_AUTH_NEGOTIATE);
   }
   else
   {
      HRESULT hr;
      SEC_WINNT_AUTH_IDENTITY Auth = { 0 };

      Auth.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
      Auth.User = (USHORT*)g_GlobalConfig.szUsername;
      Auth.Domain = (USHORT*)g_GlobalConfig.szUserDomain;
      Auth.Password = (USHORT*)g_GlobalConfig.szUserPassword;

      hr = SIZETToULong(wcslen(g_GlobalConfig.szUsername), &(Auth.UserLength));
      if (hr != S_OK)
         return FALSE;
      hr = SIZETToULong(wcslen(g_GlobalConfig.szUserDomain), &(Auth.DomainLength));
      if (hr != S_OK)
         return FALSE;
      hr = SIZETToULong(wcslen(g_GlobalConfig.szUserPassword), &(Auth.PasswordLength));
      if (hr != S_OK)
         return FALSE;

      ulResult = ldap_bind_s(pLdapHandle, NULL, (PWCHAR)&Auth, LDAP_AUTH_NEGOTIATE);
   }

   if (ulResult != LDAP_SUCCESS)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sUnable to bind to LDAP server%s (error %u: %s).", COLOR_RED, COLOR_RESET, ulResult, ldap_err2string(ulResult)
      );
      ldap_unbind(pLdapHandle);
      return NULL;
   }

   Log(
      0, LOG_LEVEL_VERBOSE,
      L"[+] %sSuccessfully bind to %s.%s", COLOR_GREEN, g_GlobalConfig.szLdapServerName, COLOR_RESET
   );

   return pLdapHandle;
}