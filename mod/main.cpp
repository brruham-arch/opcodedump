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
    static const char* info = "opcodedump|1.0|CLEO ScriptSpace Opcode Dumper|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    remove(LOGFILE);
    remove(OUTFILE);
    logf_("[OD] OnModPreLoad v1.0");
}

EXPORT void OnModLoad() {
    logf_("[OD] OnModLoad mulai");

    // Buka libCLEO — symbolnya tidak di-strip
    void* hCLEO = dlopen("libCLEO.so", RTLD_NOW | RTLD_NOLOAD);
    if (!hCLEO) hCLEO = dlopen("libCLEO.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hCLEO) { logf_("[OD] ERROR: libCLEO tidak bisa dibuka"); return; }
    logff_("[OD] hCLEO=%p", hCLEO);

    // Ambil pointer ke ScriptSpace
    // ScriptSpace = array of uint8 = bytecode buffer utama
    uint8_t** ppSpace = (uint8_t**)dlsym(hCLEO, "_ZN11CTheScripts11ScriptSpaceE");
    if (!ppSpace) { logf_("[OD] ERROR: ScriptSpace tidak ditemukan"); return; }
    logff_("[OD] ppSpace=%p", ppSpace);

    uint8_t* space = *ppSpace;
    if (!space) {
        // Mungkin ScriptSpace adalah array statis, bukan pointer
        // Coba treat ppSpace langsung sebagai buffer
        space = (uint8_t*)ppSpace;
        logf_("[OD] ScriptSpace: treat sebagai array statis");
    }
    logff_("[OD] ScriptSpace buffer=%p", space);

    // Scan buffer — format instruksi CLEO/GTA SA:
    // [2 byte opcode][parameter...]
    // Panjang parameter bervariasi per opcode, tapi kita hanya butuh opcode ID
    // Strategi: scan tiap 2 byte sebagai potential opcode, filter range valid
    // Opcode GTA SA: 0x0000 - 0x0FFF (standar) + 0x0A00-0x0FFF (CLEO extended)

    // Gunakan bitmask 4096 bit = 512 byte untuk track opcode yang sudah ditemukan
    uint8_t seen[4096 / 8] = {0};  // bit array untuk opcode 0x0000-0x0FFF
    int count = 0;

    for (size_t i = 0; i + 1 < SCRIPT_SPACE_SIZE; i += 2) {
        uint16_t opcode = (uint16_t)(space[i] | (space[i+1] << 8));

        // Strip bit 7 MSB (negasi kondisi di CLEO)
        uint16_t clean = opcode & 0x7FFF;

        // Filter range valid opcode GTA SA + CLEO
        if (clean > 0x0FFF) continue;

        // Cek apakah sudah pernah dicatat
        int idx = clean / 8;
        int bit = clean % 8;
        if (seen[idx] & (1 << bit)) continue;

        seen[idx] |= (1 << bit);
        count++;
    }

    logff_("[OD] Scan selesai, %d opcode unik ditemukan", count);

    // Tulis hasil ke file
    FILE* out = fopen(OUTFILE, "w");
    if (!out) { logf_("[OD] ERROR: tidak bisa buka output file"); return; }

    fprintf(out, "# CLEO ScriptSpace Opcode Dump\n");
    fprintf(out, "# Total opcode unik: %d\n\n", count);

    for (int op = 0; op <= 0x0FFF; op++) {
        int idx = op / 8;
        int bit = op % 8;
        if (seen[idx] & (1 << bit)) {
            fprintf(out, "0x%04X\n", op);
        }
    }

    fclose(out);
    logff_("[OD] Hasil disimpan ke %s", OUTFILE);
    logf_("[OD] OnModLoad SELESAI");
}

} // extern "C"
