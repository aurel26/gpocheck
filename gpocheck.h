//
// Macros
//
#define _HeapAlloc(x) HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, (x))
#define _SafeHeapRelease(x) { if (NULL != x) { HeapFree(g_hHeap, 0, x); x = NULL; } }

//
// Typedef
//
typedef struct _GLOBAL_CONFIG
{
   LPWSTR szLdapServerName;
   DWORD dwLdapServerPort;

   LPWSTR szUsername;
   LPWSTR szUserDomain;
   LPWSTR szUserPassword;

   LPWSTR szDefaultNamingContext;
   LPWSTR szDnsServerName;
   LPWSTR szDnsDomaineName;
   LPWSTR szSysvolPrefix;

   HANDLE hImpersonateToken;
} GLOBAL_CONFIG, *PGLOBAL_CONFIG;

//
// Global variables
//
#ifdef GLOBAL_DEFINE
#define GLOBAL_PREFIX
#define GLOBAL_NULL_SUFIX ={0}
#else
#define GLOBAL_PREFIX extern
#define GLOBAL_NULL_SUFIX
#endif

GLOBAL_PREFIX HANDLE g_hHeap GLOBAL_NULL_SUFIX;
GLOBAL_PREFIX GLOBAL_CONFIG g_GlobalConfig GLOBAL_NULL_SUFIX;
GLOBAL_PREFIX HANDLE g_hLogFile GLOBAL_NULL_SUFIX;
GLOBAL_PREFIX BOOL g_bSupportsAnsi GLOBAL_NULL_SUFIX;
GLOBAL_PREFIX PSID g_pSidAuthenticated GLOBAL_NULL_SUFIX;
GLOBAL_PREFIX PSID g_pSidSystem GLOBAL_NULL_SUFIX;
GLOBAL_PREFIX PSID g_pSidEDC GLOBAL_NULL_SUFIX;
GLOBAL_PREFIX PSID g_pSidLocalAdministrators GLOBAL_NULL_SUFIX;

//
// Log levels
//
#define LOG_LEVEL_NONE        0   // Tracing is not on
#define LOG_LEVEL_CRITICAL    1   // Abnormal exit or termination
#define LOG_LEVEL_ERROR       2   // Severe errors that need logging
#define LOG_LEVEL_WARNING     3   // Warnings such as allocation failure
#define LOG_LEVEL_INFORMATION 4   // Includes non-error cases(e.g.,Entry-Exit)
#define LOG_LEVEL_VERBOSE     5   // Detailed traces from intermediate steps
#define LOG_LEVEL_VERYVERBOSE 6

//
// Colors VT100
//
#define COLOR_RED          (g_bSupportsAnsi) ? L"\x1b[38;5;1m" : L""
#define COLOR_GREEN        (g_bSupportsAnsi) ? L"\x1b[1;32m" : L""
#define COLOR_YELLOW       (g_bSupportsAnsi) ? L"\x1b[1;33m" : L""
#define COLOR_BRIGHT_RED   (g_bSupportsAnsi) ? L"\x1b[38;5;9m" : L""
#define COLOR_MAGENTA      (g_bSupportsAnsi) ? L"\x1b[1;35m" : L""
#define COLOR_CYAN         (g_bSupportsAnsi) ? L"\x1b[1;36m" : L""
#define COLOR_WHITE        (g_bSupportsAnsi) ? L"\x1b[1;37m" : L""
#define COLOR_RESET        (g_bSupportsAnsi) ? L"\x1b[0m" : L""

//
// Functions
//
// LDAP.cpp
BOOL
LdapGetRootDseInfo(
);

BOOL
LdapGetAllGpoObjects(
);

// FileCheck.cpp
BOOL
FolderCheckRoot(
   _In_z_ LPWSTR szFolderPath
);

BOOL
FolderProcessGpo(
   _In_z_ LPWSTR szPathGpo,
   _In_z_ LPWSTR szGuid,
   _In_z_ LPWSTR szName
);

// Utils.cpp
VOID
Log(
   _In_ DWORD dwIndent,
   _In_ DWORD dwLevel,
   _In_z_ LPCWSTR szFormat,
   ...
);

VOID
StringDuplicate(
   _In_z_ LPWSTR szInput,
   _Out_ LPWSTR *szOutput
);

BOOL
ConvertNcToDns(
);

LPWSTR
ConvertAceToSddl(
   _In_ PACE_HEADER pACE
);