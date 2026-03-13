/*
 * sccm_recon.c — BOF for SCCM RECON-7 local file enumeration
 *
 * Usage:
 *   sccm_recon
 *
 * Enumerates SCCM local client paths, scrapes client logs for
 * candidate UNC paths and URLs, and reads the ManagementPoints
 * registry value when present.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "triage.h"

void go(char* args, int args_len) {
    datap parser;
    char* unused;

    BeaconDataParse(&parser, args, args_len);
    unused = BeaconDataExtract(&parser, NULL);

    if (unused && strlen(unused) > 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Usage: sccm_recon\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM RECON-7 (BOF) ===\n");
    triage_sccm_recon();
}
