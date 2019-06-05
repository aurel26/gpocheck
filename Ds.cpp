#include <Windows.h>
#include <DsGetDC.h>
#include <Lm.h>

BOOL
DsLocalteDc(
)
{
   DWORD dwResult;
   PDOMAIN_CONTROLLER_INFO pDomainControllerInfo;

   dwResult = DsGetDcName(
      NULL,                      // ComputerName
      NULL,                      // DomainName
      NULL,                      // DomainGuid
      NULL,                      // SiteName
      DS_ONLY_LDAP_NEEDED | DS_RETURN_DNS_NAME | DS_WRITABLE_REQUIRED,
      &pDomainControllerInfo
   );

   if (dwResult != ERROR_SUCCESS)
   {
      return FALSE;
   }

   NetApiBufferFree(pDomainControllerInfo);

   return TRUE;
}