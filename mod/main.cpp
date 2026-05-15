#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <android/log.h>

#define LOG_TAG "libopcodedump"
#define LOGFILE "/storage/emulated/0/opcodedump_log.txt"
#define OUTFILE "/storage/emulated/0/opcodes_found.txt"
#define EXPORT  __attribute__((visibility("default")))
#define SCRIPT_SPACE_SIZE 69905

static void logf_(const char* msg) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s", msg);
}
static void logff_(const char* fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    logf_(buf);
}

extern "C" {

EXPORT void* __GetModInfo() {
    static const char* info = "opcodedump|1.1|CLEO ScriptSpace Opcode Dumper|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    remove(LOGFILE);
    remove(OUTFILE);
    logf_("[OD] OnModPreLoad v1.1");
}

EXPORT void OnModLoad() {
    logf_("[OD] OnModLoad mulai");

    // Load Dobby untuk resolve C++ mangled symbol
    void* hDobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hDobby) { logf_("[OD] ERROR: libdobby"); return; }

    auto resolver = (void*(*)(const char*, const char*))
                        dlsym(hDobby, "DobbySymbolResolver");
    if (!resolver) { logf_("[OD] ERROR: DobbySymbolResolver"); return; }

    // Load libCLEO
    void* hCLEO = dlopen("libCLEO.so", RTLD_NOW | RTLD_NOLOAD);
    if (!hCLEO) hCLEO = dlopen("libCLEO.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hCLEO) { logf_("[OD] ERROR: libCLEO"); return; }
    logff_("[OD] hCLEO=%p", hCLEO);

    // Coba resolve via DobbySymbolResolver (lebih handal untuk mangled)
    void* pSpace = resolver("libCLEO.so", "_ZN11CTheScripts11ScriptSpaceE");
    logff_("[OD] DobbyResolver ScriptSpace=%p", pSpace);

    // Fallback: coba dlsym biasa
    if (!pSpace) {
        pSpace = dlsym(hCLEO, "_ZN11CTheScripts11ScriptSpaceE");
        logff_("[OD] dlsym ScriptSpace=%p", pSpace);
    }

    if (!pSpace) {
        logf_("[OD] ERROR: ScriptSpace tidak ditemukan via keduanya");
        return;
    }

    // ScriptSpace bisa berupa:
    // 1. Pointer ke buffer (double pointer)
    // 2. Array statis (pointer langsung ke data)
    // Coba keduanya dan log hasilnya

    uint8_t* space_direct = (uint8_t*)pSpace;
    uint8_t* space_deref  = *(uint8_t**)pSpace;

    logff_("[OD] space_direct[0..3] = %02X %02X %02X %02X",
           space_direct[0], space_direct[1],
           space_direct[2], space_direct[3]);

    if (space_deref) {
        logff_("[OD] space_deref[0..3] = %02X %02X %02X %02X",
               space_deref[0], space_deref[1],
               space_deref[2], space_deref[3]);
    }

    // Pilih buffer yang lebih masuk akal
    // Opcode pertama GTA SA main.scm biasanya 0x0002 (GOTO) atau 0x0001
    uint8_t* space = space_direct;
    uint16_t op0_direct = (uint16_t)(space_direct[0] | (space_direct[1] << 8)) & 0x7FFF;
    if (space_deref) {
        uint16_t op0_deref = (uint16_t)(space_deref[0] | (space_deref[1] << 8)) & 0x7FFF;
        // Deref lebih masuk akal jika opcode pertama dalam range valid
        if (op0_deref <= 0x0FFF && op0_direct > 0x0FFF) {
            space = space_deref;
            logf_("[OD] Pakai space_deref");
        } else {
            logf_("[OD] Pakai space_direct");
        }
    }

    // Scan opcode
    uint8_t seen[4096 / 8] = {0};
    int count = 0;

    for (size_t i = 0; i + 1 < SCRIPT_SPACE_SIZE; i += 2) {
        uint16_t opcode = (uint16_t)(space[i] | (space[i+1] << 8));
        uint16_t clean  = opcode & 0x7FFF;
        if (clean > 0x0FFF) continue;
        int idx = clean / 8;
        int bit = clean % 8;
        if (seen[idx] & (1 << bit)) continue;
        seen[idx] |= (1 << bit);
        count++;
    }

    logff_("[OD] %d opcode unik ditemukan", count);

    FILE* out = fopen(OUTFILE, "w");
    if (!out) { logf_("[OD] ERROR: fopen output"); return; }

    fprintf(out, "# CLEO ScriptSpace Opcode Dump v1.1\n");
    fprintf(out, "# Total: %d opcode unik\n\n", count);
    for (int op = 0; op <= 0x0FFF; op++) {
        if (seen[op/8] & (1 << (op%8)))
            fprintf(out, "0x%04X\n", op);
    }
    fclose(out);

    logff_("[OD] Disimpan ke %s", OUTFILE);
    logf_("[OD] SELESAI");
}

} // extern "C"
