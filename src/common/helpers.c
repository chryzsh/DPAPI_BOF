/*
 * helpers.c — Utility functions for DPAPI BOFs
 * Ported from SharpDPAPI/lib/Helpers.cs
 */
#include "helpers.h"
#include <tlhelp32.h>

#ifdef BOF
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
#endif

/* ---- Hex string to byte array ---- */
BYTE* hex_to_bytes(const char* hex, int* out_len) {
    if (!hex || !out_len) return NULL;
    int slen = strlen(hex);
    if (slen % 2 != 0) return NULL;

    int blen = slen / 2;
    BYTE* bytes = (BYTE*)intAlloc(blen);
    if (!bytes) return NULL;

    for (int i = 0; i < blen; i++) {
        unsigned int val = 0;
        char tmp[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        for (int j = 0; j < 2; j++) {
            val <<= 4;
            char c = tmp[j];
            if (c >= '0' && c <= '9') val |= (c - '0');
            else if (c >= 'a' && c <= 'f') val |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val |= (c - 'A' + 10);
            else { intFree(bytes); return NULL; }
        }
        bytes[i] = (BYTE)val;
    }
    *out_len = blen;
    return bytes;
}

/* ---- Byte array to hex string ---- */
char* bytes_to_hex(const BYTE* data, int len) {
    if (!data || len <= 0) return NULL;
    char* hex = (char*)intAlloc(len * 2 + 1);
    if (!hex) return NULL;
    for (int i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02X", data[i]);
    }
    hex[len * 2] = 0;
    return hex;
}

/* ---- Byte array comparison ---- */
BOOL byte_array_equals(const BYTE* a, const BYTE* b, int len) {
    if (!a || !b) return FALSE;
    return memcmp(a, b, len) == 0;
}

/* ---- Find needle in haystack ---- */
int array_index_of(const BYTE* haystack, int haystack_len,
                   const BYTE* needle, int needle_len) {
    if (!haystack || !needle || needle_len > haystack_len) return -1;
    for (int i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return i;
    }
    return -1;
}

/* ---- Wide string to UTF-8 ---- */
char* wide_to_utf8(const wchar_t* wstr) {
    if (!wstr) return NULL;
#ifdef BOF
    int len = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char* str = (char*)intAlloc(len);
    if (!str) return NULL;
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
#else
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char* str = (char*)intAlloc(len);
    if (!str) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
#endif
    return str;
}

/* ---- UTF-8 to wide string ---- */
wchar_t* utf8_to_wide(const char* str) {
    if (!str) return NULL;
#ifdef BOF
    int len = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len <= 0) return NULL;
    wchar_t* wstr = (wchar_t*)intAlloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
#else
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len <= 0) return NULL;
    wchar_t* wstr = (wchar_t*)intAlloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
#endif
    return wstr;
}

/* ---- String case conversion ---- */
void str_to_upper(char* str) {
    if (!str) return;
    for (; *str; str++) *str = (char)toupper((unsigned char)*str);
}

void str_to_lower(char* str) {
    if (!str) return;
    for (; *str; str++) *str = (char)tolower((unsigned char)*str);
}

static BOOL is_local_system_sid(PSID sid) {
    static const BYTE nt_authority[6] = SECURITY_NT_AUTHORITY;
    SID* parsed_sid = (SID*)sid;

    if (!parsed_sid) return FALSE;
    if (parsed_sid->Revision != SID_REVISION) return FALSE;
    if (parsed_sid->SubAuthorityCount != 1) return FALSE;
    if (memcmp(parsed_sid->IdentifierAuthority.Value, nt_authority, sizeof(nt_authority)) != 0)
        return FALSE;

    return (parsed_sid->SubAuthority[0] == SECURITY_LOCAL_SYSTEM_RID);
}

static BOOL token_is_system(HANDLE token) {
    DWORD size = 0;
    BOOL result = FALSE;

    if (!token) return FALSE;

#ifdef BOF
    ADVAPI32$GetTokenInformation(token, TokenUser, NULL, 0, &size);
#else
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
#endif
    if (size == 0) return FALSE;

    TOKEN_USER* user = (TOKEN_USER*)intAlloc(size);
    if (!user) return FALSE;

#ifdef BOF
    if (ADVAPI32$GetTokenInformation(token, TokenUser, user, size, &size)) {
#else
    if (GetTokenInformation(token, TokenUser, user, size, &size)) {
#endif
        result = is_local_system_sid(user->User.Sid);
    }

    intFree(user);
    return result;
}

/* ---- Check if running as high integrity ---- */
BOOL is_high_integrity(void) {
    HANDLE hToken = NULL;
    BOOL result = FALSE;

#ifdef BOF
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    DWORD dwSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    if (dwSize == 0) { KERNEL32$CloseHandle(hToken); return FALSE; }

    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)intAlloc(dwSize);
    if (!tml) { KERNEL32$CloseHandle(hToken); return FALSE; }

    if (ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, tml, dwSize, &dwSize)) {
        DWORD* pCount = (DWORD*)ADVAPI32$GetSidSubAuthorityCount(tml->Label.Sid);
        DWORD integrity = *ADVAPI32$GetSidSubAuthority(tml->Label.Sid, *pCount - 1);
        result = (integrity >= SECURITY_MANDATORY_HIGH_RID);
    }

    intFree(tml);
    KERNEL32$CloseHandle(hToken);
#else
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    if (dwSize == 0) { CloseHandle(hToken); return FALSE; }

    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)intAlloc(dwSize);
    if (!tml) { CloseHandle(hToken); return FALSE; }

    if (GetTokenInformation(hToken, TokenIntegrityLevel, tml, dwSize, &dwSize)) {
        DWORD* pCount = GetSidSubAuthorityCount(tml->Label.Sid);
        DWORD integrity = *GetSidSubAuthority(tml->Label.Sid, *pCount - 1);
        result = (integrity >= SECURITY_MANDATORY_HIGH_RID);
    }

    intFree(tml);
    CloseHandle(hToken);
#endif

    return result;
}

BOOL is_system(void) {
    HANDLE hToken = NULL;
    BOOL result = FALSE;

#ifdef BOF
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    result = token_is_system(hToken);
    KERNEL32$CloseHandle(hToken);
#else
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    result = token_is_system(hToken);
    CloseHandle(hToken);
#endif

    return result;
}

static BOOL impersonate_system_process(const wchar_t* process_name) {
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32W pe32;
    BOOL result = FALSE;

    if (!process_name) return FALSE;

    memset(&pe32, 0, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);

#ifdef BOF
    hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    if (!KERNEL32$Process32FirstW(hSnapshot, &pe32)) {
        KERNEL32$CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        HANDLE hProcess = NULL;
        HANDLE hToken = NULL;
        HANDLE hDupToken = NULL;

        if (_wcsicmp(pe32.szExeFile, process_name) != 0) continue;

        hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) continue;

        if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken))
            goto cleanup_process_bof;
        if (!token_is_system(hToken)) goto cleanup_process_bof;
        if (!ADVAPI32$DuplicateToken(hToken, SecurityImpersonation, &hDupToken))
            goto cleanup_process_bof;
        if (ADVAPI32$ImpersonateLoggedOnUser(hDupToken)) {
            result = TRUE;
        }

cleanup_process_bof:
        if (hDupToken) KERNEL32$CloseHandle(hDupToken);
        if (hToken) KERNEL32$CloseHandle(hToken);
        if (hProcess) KERNEL32$CloseHandle(hProcess);
        if (result) break;
    } while (KERNEL32$Process32NextW(hSnapshot, &pe32));

    KERNEL32$CloseHandle(hSnapshot);
#else
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        HANDLE hProcess = NULL;
        HANDLE hToken = NULL;
        HANDLE hDupToken = NULL;

        if (_wcsicmp(pe32.szExeFile, process_name) != 0) continue;

        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
        if (!hProcess) continue;

        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken))
            goto cleanup_process;
        if (!token_is_system(hToken)) goto cleanup_process;
        if (!DuplicateToken(hToken, SecurityImpersonation, &hDupToken))
            goto cleanup_process;
        if (ImpersonateLoggedOnUser(hDupToken)) {
            result = TRUE;
        }

cleanup_process:
        if (hDupToken) CloseHandle(hDupToken);
        if (hToken) CloseHandle(hToken);
        if (hProcess) CloseHandle(hProcess);
        if (result) break;
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
#endif

    return result;
}

/* ---- Elevate to SYSTEM via token impersonation ---- */
BOOL get_system(void) {
    static const wchar_t* candidates[] = {
        L"winlogon.exe",
        L"services.exe",
        L"svchost.exe",
        L"spoolsv.exe"
    };

    if (is_system()) return TRUE;

    for (int i = 0; i < (int)(sizeof(candidates) / sizeof(candidates[0])); i++) {
        if (impersonate_system_process(candidates[i])) return TRUE;
    }

    return FALSE;
}

/* ---- Revert to original token ---- */
BOOL revert_to_self_helper(void) {
#ifdef BOF
    return ADVAPI32$RevertToSelf();
#else
    return RevertToSelf();
#endif
}

/* ---- Get user profile folders ---- */
wchar_t** get_user_folders(int* count) {
    /* Enumerate C:\Users\* directories */
    wchar_t search_path[] = L"C:\\Users\\*";
    WIN32_FIND_DATAW ffd;
    HANDLE hFind;
    wchar_t** folders = NULL;
    int n = 0;
    int capacity = 16;

    folders = (wchar_t**)intAlloc(capacity * sizeof(wchar_t*));
    if (!folders) { *count = 0; return NULL; }

#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search_path, &ffd);
#else
    hFind = FindFirstFileW(search_path, &ffd);
#endif
    if (hFind == INVALID_HANDLE_VALUE) { *count = 0; return folders; }

    do {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;
        if (_wcsicmp(ffd.cFileName, L"Public") == 0) continue;
        if (_wcsicmp(ffd.cFileName, L"Default") == 0) continue;
        if (_wcsicmp(ffd.cFileName, L"Default User") == 0) continue;
        if (_wcsicmp(ffd.cFileName, L"All Users") == 0) continue;

        if (n >= capacity) {
            capacity *= 2;
            folders = (wchar_t**)intRealloc(folders, capacity * sizeof(wchar_t*));
        }

        /* Build full path */
        int plen = 9 + wcslen(ffd.cFileName) + 1; /* "C:\\Users\\" + name + null */
        wchar_t* path = (wchar_t*)intAlloc(plen * sizeof(wchar_t));
        if (path) {
            swprintf(path, L"C:\\Users\\%s", ffd.cFileName);
            folders[n++] = path;
        }

#ifdef BOF
    } while (KERNEL32$FindNextFileW(hFind, &ffd));
    KERNEL32$FindClose(hFind);
#else
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
#endif

    *count = n;
    return folders;
}

/* ---- Read registry key value ---- */
BOOL get_reg_key_value(HKEY root, const wchar_t* path, const wchar_t* name,
                       BYTE** out_data, DWORD* out_len) {
    HKEY hKey = NULL;
    LONG status;
    DWORD type = 0, size = 0;

#ifdef BOF
    status = ADVAPI32$RegOpenKeyExW(root, path, 0, KEY_READ, &hKey);
#else
    status = RegOpenKeyExW(root, path, 0, KEY_READ, &hKey);
#endif
    if (status != ERROR_SUCCESS) return FALSE;

#ifdef BOF
    status = ADVAPI32$RegQueryValueExW(hKey, name, NULL, &type, NULL, &size);
#else
    status = RegQueryValueExW(hKey, name, NULL, &type, NULL, &size);
#endif
    if (status != ERROR_SUCCESS || size == 0) {
#ifdef BOF
        ADVAPI32$RegCloseKey(hKey);
#else
        RegCloseKey(hKey);
#endif
        return FALSE;
    }

    BYTE* data = (BYTE*)intAlloc(size);
    if (!data) {
#ifdef BOF
        ADVAPI32$RegCloseKey(hKey);
#else
        RegCloseKey(hKey);
#endif
        return FALSE;
    }

#ifdef BOF
    status = ADVAPI32$RegQueryValueExW(hKey, name, NULL, &type, data, &size);
    ADVAPI32$RegCloseKey(hKey);
#else
    status = RegQueryValueExW(hKey, name, NULL, &type, data, &size);
    RegCloseKey(hKey);
#endif

    if (status != ERROR_SUCCESS) {
        intFree(data);
        return FALSE;
    }

    *out_data = data;
    *out_len = size;
    return TRUE;
}

/* ---- Parse masterkey file structure ---- */
BOOL parse_masterkey_file(const BYTE* data, int data_len,
                          BYTE** masterkey_bytes, int* mk_len,
                          BYTE** backup_bytes, int* bk_len,
                          BYTE** domain_key_bytes, int* dk_len,
                          GUID* master_key_guid) {
    /*
     * Masterkey file layout:
     * [0-3]   version (2)
     * [4-7]   reserved
     * [8-11]  reserved
     * [12-75] GUID string (64 bytes, wide)
     * [76-79] reserved
     * [80-83] policy flags
     * [84-91] masterkey len
     * [92-99] backupkey len
     * [100-107] credhistory len
     * [108-115] domainkey len
     * [116+]  masterkey blob, then backup, then credhistory, then domainkey
     */
    if (!data || data_len < 128 ||
        !masterkey_bytes || !mk_len ||
        !backup_bytes || !bk_len ||
        !domain_key_bytes || !dk_len) {
        return FALSE;
    }

    *masterkey_bytes = NULL; *mk_len = 0;
    *backup_bytes = NULL; *bk_len = 0;
    *domain_key_bytes = NULL; *dk_len = 0;
    if (master_key_guid) memset(master_key_guid, 0, sizeof(GUID));

    /*
     * Layout A (older parsing):
     * lengths at 84/92/100/108 (DWORD), payload starts at 116
     *
     * Layout B (SharpSCCM/SharpDPAPI):
     * lengths at 96/104/112/120 (QWORD), payload starts at 128
     */
    int offset = 0;
    int mk_size = 0, bk_size = 0, ch_size = 0, dk_size = 0;

    BOOL parsed = FALSE;

    /* Try Layout B first */
    if (data_len >= 128) {
        ULONGLONG mk64 = *(ULONGLONG*)(data + 96);
        ULONGLONG bk64 = *(ULONGLONG*)(data + 104);
        ULONGLONG ch64 = *(ULONGLONG*)(data + 112);
        ULONGLONG dk64 = *(ULONGLONG*)(data + 120);

        if (mk64 > 0 && mk64 <= 0x7FFFFFFF &&
            bk64 <= 0x7FFFFFFF &&
            ch64 <= 0x7FFFFFFF &&
            dk64 <= 0x7FFFFFFF) {
            int off = 128;
            int m = (int)mk64, b = (int)bk64, c = (int)ch64, d = (int)dk64;
            if (off + m + b + c + d <= data_len) {
                offset = off;
                mk_size = m; bk_size = b; ch_size = c; dk_size = d;
                parsed = TRUE;
            }
        }
    }

    /* Fallback Layout A */
    if (!parsed && data_len >= 116) {
        DWORD mk32 = *(DWORD*)(data + 84);
        DWORD bk32 = *(DWORD*)(data + 92);
        DWORD ch32 = *(DWORD*)(data + 100);
        DWORD dk32 = *(DWORD*)(data + 108);
        int off = 116;
        int m = (int)mk32, b = (int)bk32, c = (int)ch32, d = (int)dk32;
        if (m > 0 && off + m + b + c + d <= data_len) {
            offset = off;
            mk_size = m; bk_size = b; ch_size = c; dk_size = d;
            parsed = TRUE;
        }
    }

    if (!parsed) return FALSE;

    if (mk_size > 0) {
        *masterkey_bytes = (BYTE*)intAlloc(mk_size);
        if (!*masterkey_bytes) return FALSE;
        memcpy(*masterkey_bytes, data + offset, mk_size);
        *mk_len = mk_size;
    }
    offset += mk_size;

    if (bk_size > 0 && offset + bk_size <= data_len) {
        *backup_bytes = (BYTE*)intAlloc(bk_size);
        if (*backup_bytes) {
            memcpy(*backup_bytes, data + offset, bk_size);
            *bk_len = bk_size;
        }
    }
    offset += bk_size;

    offset += ch_size;

    if (dk_size > 0 && offset + dk_size <= data_len) {
        *domain_key_bytes = (BYTE*)intAlloc(dk_size);
        if (*domain_key_bytes) {
            memcpy(*domain_key_bytes, data + offset, dk_size);
            *dk_len = dk_size;
        }
    }

    return (*masterkey_bytes != NULL && *mk_len > 0);
}

/* ---- Base64 decode using CryptStringToBinaryA ---- */
BYTE* base64_decode(const char* input, int* out_len) {
    if (!input || !out_len) return NULL;
    DWORD size = 0;

#ifdef BOF
    if (!CRYPT32$CryptStringToBinaryA(input, 0, 0x00000001 /* CRYPT_STRING_BASE64 */, NULL, &size, NULL, NULL))
        return NULL;

    BYTE* output = (BYTE*)intAlloc(size);
    if (!output) return NULL;

    if (!CRYPT32$CryptStringToBinaryA(input, 0, 0x00000001, output, &size, NULL, NULL)) {
        intFree(output);
        return NULL;
    }
#else
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL))
        return NULL;

    BYTE* output = (BYTE*)intAlloc(size);
    if (!output) return NULL;

    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, output, &size, NULL, NULL)) {
        intFree(output);
        return NULL;
    }
#endif

    *out_len = (int)size;
    return output;
}

/* ---- Base64 encode using CryptBinaryToStringA ---- */
char* base64_encode(const BYTE* data, int len) {
    if (!data || len <= 0) return NULL;
    DWORD size = 0;

#ifdef BOF
    if (!CRYPT32$CryptBinaryToStringA(data, len, 0x00000001 | 0x40000000 /* BASE64 | NOCRLF */, NULL, &size))
        return NULL;

    char* output = (char*)intAlloc(size + 1);
    if (!output) return NULL;

    if (!CRYPT32$CryptBinaryToStringA(data, len, 0x00000001 | 0x40000000, output, &size)) {
        intFree(output);
        return NULL;
    }
#else
    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size))
        return NULL;

    char* output = (char*)intAlloc(size + 1);
    if (!output) return NULL;

    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, output, &size)) {
        intFree(output);
        return NULL;
    }
#endif

    return output;
}

/* ---- GUID string check ---- */
BOOL is_guid(const char* str) {
    if (!str) return FALSE;
    int len = strlen(str);
    /* GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars) */
    /* or {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} (38 chars) */
    if (len != 36 && len != 38) return FALSE;
    return TRUE;  /* Simplified check */
}

/* ---- GUID to string ---- */
char* guid_to_string(const GUID* guid) {
    if (!guid) return NULL;
    char* str = (char*)intAlloc(40);
    if (!str) return NULL;
    sprintf(str, "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
            guid->Data1, guid->Data2, guid->Data3,
            guid->Data4[0], guid->Data4[1],
            guid->Data4[2], guid->Data4[3],
            guid->Data4[4], guid->Data4[5],
            guid->Data4[6], guid->Data4[7]);
    return str;
}

/* ---- String to GUID ---- */
BOOL string_to_guid(const char* str, GUID* out) {
    if (!str || !out) return FALSE;
    memset(out, 0, sizeof(GUID));

    /* Skip leading { if present */
    const char* p = str;
    if (*p == '{') p++;

    unsigned int d1, d2, d3;
    unsigned int d4[8];
    int n = sscanf(p, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   &d1, &d2, &d3,
                   &d4[0], &d4[1], &d4[2], &d4[3],
                   &d4[4], &d4[5], &d4[6], &d4[7]);
    if (n != 11) return FALSE;

    out->Data1 = (DWORD)d1;
    out->Data2 = (unsigned short)d2;
    out->Data3 = (unsigned short)d3;
    for (int i = 0; i < 8; i++) out->Data4[i] = (BYTE)d4[i];
    return TRUE;
}

/* ---- Extract SID from file path ---- */
char* extract_sid_from_path(const wchar_t* path) {
    /* Look for S-1-5-21-... pattern in the path */
    if (!path) return NULL;

    const wchar_t* sid_start = wcsstr(path, L"S-1-5-21-");
    if (!sid_start) return NULL;

    /* Find end of SID */
    const wchar_t* ep = sid_start;
    while (*ep && *ep != L'\\' && *ep != L'/') ep++;

    int sid_len = (int)(ep - sid_start);
    char* sid = (char*)intAlloc(sid_len + 1);
    if (!sid) return NULL;

    for (int i = 0; i < sid_len; i++) {
        sid[i] = (char)sid_start[i];
    }
    sid[sid_len] = 0;
    return sid;
}
