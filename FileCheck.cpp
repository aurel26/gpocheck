#include <Windows.h>
#include <sddl.h>
#include <Aclapi.h>
#include <stdio.h>
#include "gpocheck.h"

LPCWSTR g_szSddlPolicies = L"O:BAG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GXGR;;;AU)(A;;0x1200a9;;;AU)(A;OICIIO;GA;;;SY)(A;;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1e01bf;;;BA)(A;OICIIO;GXGR;;;SO)(A;;0x1200a9;;;SO)(A;;0x1201bf;;;PA)(A;OICIIO;GXGWGR;;;PA)";

GENERIC_MAPPING g_FileMap =
{
   FILE_GENERIC_READ,
   FILE_GENERIC_WRITE,
   FILE_GENERIC_EXECUTE,
   FILE_ALL_ACCESS
};

PSECURITY_DESCRIPTOR
GetFileSd (
   _In_z_ LPWSTR szFilePath
)
{
   BOOL bResult;
   DWORD dwSize;
   PSECURITY_DESCRIPTOR pSd;

   bResult = GetFileSecurity(
      szFilePath,
      OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      NULL,
      0,
      &dwSize
   );
   if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sGetFileSecurity(%s) failed%s (error %u).",
         COLOR_RED, szFilePath, COLOR_RESET, GetLastError()
      );
      return NULL;
   }

   pSd = HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwSize);

   bResult = GetFileSecurity(
      szFilePath,
      OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      pSd,
      dwSize,
      &dwSize
   );
   if (bResult == FALSE)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sGetFileSecurity(%s) failed%s (error %u).",
         COLOR_RED, szFilePath, COLOR_RESET, GetLastError()
      );
      _SafeHeapRelease(pSd);
      return NULL;
   }

   return pSd;
}

BOOL
CheckSD (
   _In_z_ LPWSTR szFilePath,
   _In_z_ LPCTSTR szSddl
)
{
   BOOL bResult;
   DWORD dwSize;

   PSECURITY_DESCRIPTOR pSdFile, pSdRef;

   pSdFile = GetFileSd(szFilePath);
   if (pSdFile == NULL)
      return FALSE;

   bResult = ConvertStringSecurityDescriptorToSecurityDescriptor(szSddl, SDDL_REVISION_1, &pSdRef, &dwSize);
   if (bResult == FALSE)
      return FALSE;

   LocalFree(pSdRef);
   _SafeHeapRelease(pSdFile);

   return TRUE;
}

BOOL
FileCheckPermission (
   _In_z_ LPWSTR szBase,
   _In_z_ LPWSTR szRelPath,
   _In_z_ LPWSTR szGuid,
   _In_z_ LPWSTR szName,
   _In_ PSID pSidOwnerGpo
)
{
   BOOL bReturn = FALSE;
   BOOL bResult;
   DWORD dwResult;

   PSECURITY_DESCRIPTOR pSd = NULL;
   SECURITY_DESCRIPTOR_CONTROL SdControl;
   PSID pSidOwner;
   BOOL bOwnerDefaulted;
   DWORD dwAttributes;
   DWORD dwRevision;
   BOOL bPresent, bDefault;
   PACL pAcl;

   WCHAR szFullPath[MAX_PATH];

   swprintf(szFullPath, MAX_PATH, L"%s\\%s", szBase, szRelPath);

   pSd = GetFileSd(szFullPath);
   if (pSd == NULL)
      goto End;

   dwAttributes = GetFileAttributes(szFullPath);
   if (dwAttributes == INVALID_FILE_ATTRIBUTES)
      goto End;

   //
   // Check Control
   //
   bResult = GetSecurityDescriptorControl(pSd, &SdControl, &dwRevision);
   if (bResult == FALSE)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %s'%s\\%s' (%s)%s %s() failed%s (error %u).",
         COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
         COLOR_RED, COLOR_RESET, GetLastError()
      );
      goto End;
   }

   if (SdControl != (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED))
   {
      //
      // Control on SYSVOL GPO sub file. Must be NOT SE_DACL_PROTECTED and SE_DACL_AUTO_INHERITED
      //
      if ((SdControl & SE_DACL_PROTECTED) == SE_DACL_PROTECTED)
         Log(
            1, LOG_LEVEL_WARNING,
            L"[x] %s'%s\\%s' (%s)%s %s\n      DACL is protected%s.",
            COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
            COLOR_BRIGHT_RED, COLOR_RESET
         );

      if ((SdControl & SE_DACL_AUTO_INHERITED) == 0)
         Log(
            1, LOG_LEVEL_WARNING,
            L"[x] %s'%s\\%s' (%s)%s %s\n      DACL is not auto inherited%s.",
            COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
            COLOR_BRIGHT_RED, COLOR_RESET
         );
   }

   //
   // Check Owner
   //
   bResult = GetSecurityDescriptorOwner(pSd, &pSidOwner, &bOwnerDefaulted);
   if (bResult == FALSE)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %s'%s\\%s' (%s)%s %sGetSecurityDescriptorOwner() failed%s (error %u).",
         COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
         COLOR_RED, COLOR_RESET, GetLastError()
      );
      goto End;
   }

   //
   // Bypass owner check if owner is S-1-5-32-544
   //
   bResult = EqualSid(pSidOwner, g_pSidLocalAdministrators);
   if (bResult == FALSE)
   {
      bResult = EqualSid(pSidOwnerGpo, pSidOwner);
      if (bResult == FALSE)
      {
         LPWSTR szSidOwnerGpo;
         LPWSTR szSidOwner;

         ConvertSidToStringSid(pSidOwnerGpo, &szSidOwnerGpo);
         ConvertSidToStringSid(pSidOwner, &szSidOwner);

         Log(
            1, LOG_LEVEL_WARNING,
            L"[x] %s'%s\\%s' (%s)%s %s\n      Owner SID (%s) is different from parent (%s)%s.",
            COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
            COLOR_BRIGHT_RED, szSidOwner, szSidOwnerGpo, COLOR_RESET
         );

         LocalFree(szSidOwnerGpo);
         LocalFree(szSidOwner);
      }
   }
   //
   // Check DACL and Inheritance
   //
   bResult = GetSecurityDescriptorDacl(pSd, &bPresent, &pAcl, &bDefault);
   if (bResult == FALSE)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %s'%s\\%s' (%s)%s %sGetSecurityDescriptorDacl() failed%s (error %u).",
         COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
         COLOR_RED, COLOR_RESET, GetLastError()
      );
      goto End;
   }

   if (pAcl == NULL)
   {
      Log(
         1, LOG_LEVEL_WARNING,
         L"[x] %s'%s\\%s' (%s)%s %s\n      has NULL DACL%s.",
         COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
         COLOR_BRIGHT_RED, COLOR_RESET
      );
   }
   else if (pAcl->AceCount > 0)
   {
      PINHERITED_FROM pInheritedFrom = NULL;

      //
      // DACL first check: all ACEs must be inherited
      //
      for (DWORD i = 0; i < pAcl->AceCount; i++)
      {
         PACE_HEADER pAce;

         bResult = GetAce(pAcl, i, (LPVOID*)&pAce);

         if ((pAce->AceFlags & INHERITED_ACE) == 0)
         {
            LPWSTR szSddl;

            bResult = GetAce(pAcl, i, (LPVOID*)&pAce);
            szSddl = ConvertAceToSddl(pAce);

            if (szSddl)
            {
               LPWSTR szSddlAce;

               szSddlAce = wcschr(szSddl, 0x28);     // 0x28 -> '('
               Log(
                  1, LOG_LEVEL_WARNING,
                  L"[x] %s'%s\\%s' (%s)%s %s\n      has not inherited ACE%s %s.",
                  COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
                  COLOR_BRIGHT_RED, COLOR_RESET, szSddlAce
               );
               LocalFree(szSddl);
            }
            else
            {
               Log(
                  1, LOG_LEVEL_WARNING,
                  L"[x] %s'%s\\%s' (%s)%s %s\n      has not inherited ACE%s.",
                  COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
                  COLOR_BRIGHT_RED, COLOR_RESET
               );
            }
         }
      }

      //
      // DACL second check: inheritance
      //
      pInheritedFrom = (PINHERITED_FROM)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, sizeof(INHERITED_FROM) * pAcl->AceCount);
      if (pInheritedFrom == NULL)
         goto End;

      dwResult = GetInheritanceSource(
         szFullPath,
         SE_FILE_OBJECT,
         DACL_SECURITY_INFORMATION,
         dwAttributes & FILE_ATTRIBUTE_DIRECTORY ? TRUE : FALSE,
         NULL,
         0,
         pAcl,
         NULL,
         &g_FileMap,
         pInheritedFrom
      );

      if (dwResult != ERROR_SUCCESS)
      {
         Log(
            0, LOG_LEVEL_ERROR,
            L"[!] %s'%s\\%s' (%s)%s %sGetInheritanceSource() failed%s (error %u).",
            COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
            COLOR_RED, COLOR_RESET, GetLastError()
         );
         goto End;
      }
      else
      {
         WCHAR szBaseWithSlash[MAX_PATH];

         // Note: INHERITED_FROM.AncestorName terminates with '\'. Build szBaseWithSlash to compare results
         swprintf_s(szBaseWithSlash, MAX_PATH, L"%s\\", szBase);

         for (DWORD i = 0; i < pAcl->AceCount; i++)
         {
            PACE_HEADER pAce;
            LPWSTR szSddl, szSddlAce;

            if ((pInheritedFrom[i].AncestorName == NULL) || (pInheritedFrom[i].GenerationGap == -1))
            {
               bResult = GetAce(pAcl, i, (LPVOID*)&pAce);
               szSddl = ConvertAceToSddl(pAce);

               if (szSddl)
               {
                  szSddlAce = wcschr(szSddl, 0x28);     // 0x28 -> '('
                  Log(
                     1, LOG_LEVEL_WARNING,
                     L"[x] %s'%s\\%s' (%s)%s %s\n      has unknown parent ACE%s %s.",
                     COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
                     COLOR_BRIGHT_RED, COLOR_RESET, szSddlAce
                  );
                  LocalFree(szSddl);
               }
               else
               {
                  Log(
                     1, LOG_LEVEL_WARNING,
                     L"[x] %s'%s\\%s' (%s)%s %s\n      has unknown parent ACE%s.",
                     COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
                     COLOR_BRIGHT_RED, COLOR_RESET
                  );
               }
            }
            else if (_wcsicmp(szBaseWithSlash, pInheritedFrom[i].AncestorName) != 0)      // Different from root GPO directory
            {
               bResult = GetAce(pAcl, i, (LPVOID*)&pAce);
               szSddl = ConvertAceToSddl(pAce);

               if (szSddl)
               {
                  szSddlAce = wcschr(szSddl, 0x28);     // 0x28 -> '('
                  Log(
                     1, LOG_LEVEL_WARNING,
                     L"[x] %s'%s\\%s' (%s)%s %s\n      has wrong parent ACE%s %s.",
                     COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
                     COLOR_BRIGHT_RED, COLOR_RESET, szSddlAce
                  );
                  LocalFree(szSddl);
               }
               else
               {
                  Log(
                     1, LOG_LEVEL_WARNING,
                     L"[x] %s'%s\\%s' (%s)%s %s\n      has wrong parent ACE%s.",
                     COLOR_WHITE, szGuid, szRelPath, szName, COLOR_RESET,
                     COLOR_BRIGHT_RED, COLOR_RESET
                  );
               }
            }
         }

         FreeInheritedFromArray(pInheritedFrom, pAcl->AceCount, NULL);
         _SafeHeapRelease(pInheritedFrom);
      }
   }

   bReturn = TRUE;

End:
   _SafeHeapRelease(pSd);

   return bReturn;
}

BOOL
ProcessDirectory (
   _In_z_ LPWSTR szBase,
   _In_opt_z_ LPWSTR szRelPath,
   _In_z_ LPWSTR szGuid,
   _In_z_ LPWSTR szName,
   _In_ PSID pSidOwnerGpo
)
{
   WCHAR szSearchPath[MAX_PATH];
   HANDLE hFindFile;
   WIN32_FIND_DATA FindData = { 0 };

   if (szRelPath == NULL)
      swprintf_s(szSearchPath, MAX_PATH, L"%s\\*", szBase);
   else
      swprintf_s(szSearchPath, MAX_PATH, L"%s\\%s\\*", szBase, szRelPath);

   hFindFile = FindFirstFile(szSearchPath, &FindData);
   if (hFindFile == INVALID_HANDLE_VALUE)
   {
      if (szRelPath == NULL)
         Log(
            0, LOG_LEVEL_ERROR,
            L"[!] FindFirstFile(%s) failed (error %u).",
            COLOR_RED, szBase, COLOR_RESET, GetLastError()
         );
      else
         Log(
            0, LOG_LEVEL_ERROR,
            L"[!] FindFirstFile(%s) failed (error %u).",
            COLOR_RED, szRelPath, COLOR_RESET, GetLastError()
         );
      return FALSE;
   }
   else
   {
      do
      {
         WCHAR sdNewRelPath[MAX_PATH];

         if (szRelPath == NULL)
            swprintf_s(sdNewRelPath, MAX_PATH, L"%s", FindData.cFileName);
         else
            swprintf_s(sdNewRelPath, MAX_PATH, L"%s\\%s", szRelPath, FindData.cFileName);

         if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
         {
            if ((wcscmp(FindData.cFileName, L".")) && (wcscmp(FindData.cFileName, L"..")))
            {
               ProcessDirectory(szBase, sdNewRelPath, szGuid, szName, pSidOwnerGpo);
            }
         }
         else
         {
            FileCheckPermission(szBase, sdNewRelPath, szGuid, szName, pSidOwnerGpo);
         }
      } while (FindNextFile(hFindFile, &FindData) != 0);

      FindClose(hFindFile);
   }

   return TRUE;
}

BOOL
FolderProcessGpo (
   _In_z_ LPWSTR szPathGpo,
   _In_z_ LPWSTR szGuid,
   _In_z_ LPWSTR szName
)
{
   BOOL bResult;

   DWORD dwRevision;
   PSECURITY_DESCRIPTOR pSd;
   SECURITY_DESCRIPTOR_CONTROL SdControl;
   PSID pSidOwner;
   BOOL bOwnerDefaulted;

   //
   // Get Security Descriptor
   //
   pSd = GetFileSd(szPathGpo);
   if (pSd == NULL)
      return FALSE;

   //
   // Get Owner
   //
   bResult = GetSecurityDescriptorOwner(pSd, &pSidOwner, &bOwnerDefaulted);
   if (bResult == FALSE)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %s'%s' (%s)%s %sGetSecurityDescriptorOwner() failed%s (error %u).",
         COLOR_WHITE, szGuid, szName, COLOR_RESET,
         COLOR_RED, COLOR_RESET, GetLastError()
      );
      _SafeHeapRelease(pSd);
      return FALSE;
   }

   //
   // Check SD Control
   //
   bResult = GetSecurityDescriptorControl(pSd, &SdControl, &dwRevision);
   if (bResult == FALSE)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %s'%s' (%s)%s %sGetSecurityDescriptorControl() failed%s (error %u).",
         COLOR_WHITE, szGuid, szName, COLOR_RESET,
         COLOR_RED, COLOR_RESET, GetLastError()
      );
      _SafeHeapRelease(pSd);
      return FALSE;
   }

   if (SdControl != (SE_SELF_RELATIVE | SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_PRESENT))
   {
      //
      // Control on SYSVOL GPO folder. Must be SE_DACL_PROTECTED and SE_DACL_AUTO_INHERITED
      //
      if ((SdControl & SE_DACL_PROTECTED) == 0)
         Log(
            1, LOG_LEVEL_WARNING,
            L"[x] %s'%s' (%s)%s %sDACL is not protected%s.",
            COLOR_WHITE, szGuid, szName, COLOR_RESET,
            COLOR_BRIGHT_RED, COLOR_RESET
         );

      if ((SdControl & SE_DACL_AUTO_INHERITED) == 0)
         Log(
            1, LOG_LEVEL_WARNING,
            L"[x] %s'%s' (%s)%s %sDACL is not auto inherited%s.",
            COLOR_WHITE, szGuid, szName, COLOR_RESET,
            COLOR_BRIGHT_RED, COLOR_RESET
         );
   }

   //
   // Check files and sub-folders
   //
   ProcessDirectory(szPathGpo, NULL, szGuid, szName, pSidOwner);

   //
   // Release
   //
   _SafeHeapRelease(pSd);

   return TRUE;
}

BOOL
FolderCheckRoot (
   _In_z_ LPWSTR szRoot
)
{
   HANDLE hFindFile;
   WCHAR szSearchPath[MAX_PATH];
   WIN32_FIND_DATA FindData = { 0 };

   CheckSD(szRoot, g_szSddlPolicies);

   swprintf_s(szSearchPath, L"%s\\*", szRoot);

   hFindFile = FindFirstFile(szSearchPath, &FindData);
   if (hFindFile == INVALID_HANDLE_VALUE)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sFindFirstFile(%s) failed%s (error %u).",
         COLOR_RED, szSearchPath, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }
   else
   {
      do
      {
         if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
         {
            if ((wcscmp(FindData.cFileName, L".")) && (wcscmp(FindData.cFileName, L"..")))
            {
               HRESULT hr;
               CLSID Guid;

               hr = CLSIDFromString(FindData.cFileName, &Guid);
               if (hr == NOERROR)
               {
                  WCHAR szFullPath[MAX_PATH];

                  swprintf(szFullPath, MAX_PATH, L"%s\\%s", szRoot, FindData.cFileName);
                  FolderProcessGpo(szFullPath, NULL, FindData.cFileName);
               }
               else
               {
                  printf_s("[x] Invalid GUID '%S' (error 0x%x)\n", FindData.cFileName, hr);
               }
            }
         }
         else
         {
            printf_s("[x] File '%S' is present in SYSVOL root directory.\n", FindData.cFileName);
         }
      } while (FindNextFile(hFindFile, &FindData) != 0);

      FindClose(hFindFile);
   }

   return TRUE;
}

BOOL
CheckFolder (
   _In_z_ LPWSTR szFolderPath
)
{
   DWORD dwAttributes;

   dwAttributes = GetFileAttributes(szFolderPath);
   if (dwAttributes == INVALID_FILE_ATTRIBUTES)
   {
      Log(
         0, LOG_LEVEL_ERROR,
         L"[!] %sGetFileAttributes(%s) failed%s (error %u).",
         COLOR_RED, szFolderPath, COLOR_RESET, GetLastError()
      );
      return FALSE;
   }
   else
   {
      if ((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
      {
         Log(
            0, LOG_LEVEL_ERROR,
            L"[!] %sInput '%s' must be a directory%s.",
            COLOR_RED, szFolderPath, COLOR_RESET
         );
         return FALSE;
      }
   }

   FolderCheckRoot(szFolderPath);

   return TRUE;
}