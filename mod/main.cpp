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

// Pointer ke ScriptSpace buffer
static uint8_t* g_scriptspace = nullptr;

// Original LoadAllScripts
typedef void (*LoadAllScripts_t)(uint8_t*, uint32_t);
static LoadAllScripts_t orig_LoadAllScripts = nullptr;

static void do_scan() {
    if (!g_scriptspace) { logf_("[OD] ERROR: scriptspace null"); return; }

    uint8_t seen[4096 / 8] = {0};
    int count = 0;

    for (size_t i = 0; i + 1 < SCRIPT_SPACE_SIZE; i += 2) {
        uint16_t opcode = (uint16_t)(g_scriptspace[i] | (g_scriptspace[i+1] << 8));
        uint16_t clean  = opcode & 0x7FFF;
        if (clean > 0x0FFF) continue;
        if (clean == 0x0000) continue; // skip padding nol
        int idx = clean / 8;
        int bit = clean % 8;
        if (seen[idx] & (1 << bit)) continue;
        seen[idx] |= (1 << bit);
        count++;
    }

    logff_("[OD] %d opcode unik ditemukan", count);

    FILE* out = fopen(OUTFILE, "w");
    if (!out) { logf_("[OD] ERROR: fopen output"); return; }
    fprintf(out, "# CLEO ScriptSpace Opcode Dump\n");
    fprintf(out, "# Total: %d opcode unik\n\n", count);
    for (int op = 1; op <= 0x0FFF; op++) {
        if (seen[op/8] & (1 << (op%8)))
            fprintf(out, "0x%04X\n", op);
    }
    fclose(out);
    logff_("[OD] Disimpan ke %s", OUTFILE);
}

// Hook LoadAllScripts — dipanggil setelah CLEO isi ScriptSpace
static void hook_LoadAllScripts(uint8_t* buf, uint32_t size) {
    logff_("[OD] LoadAllScripts dipanggil buf=%p size=%u", buf, size);
    orig_LoadAllScripts(buf, size);
    logf_("[OD] LoadAllScripts selesai, mulai scan...");
    do_scan();
}

extern "C" {

EXPORT void* __GetModInfo() {
    static const char* info = "opcodedump|1.2|CLEO Opcode Dumper via LoadAllScripts hook|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    remove(LOGFILE);
    remove(OUTFILE);
    logf_("[OD] OnModPreLoad v1.2");
}

EXPORT void OnModLoad() {
    logf_("[OD] OnModLoad mulai");

    void* hDobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hDobby) { logf_("[OD] ERROR: libdobby"); return; }
    auto resolver  = (void*(*)(const char*,const char*))dlsym(hDobby, "DobbySymbolResolver");
    auto dobbyHook = (int(*)(void*,void*,void**))dlsym(hDobby, "DobbyHook");
    if (!resolver || !dobbyHook) { logf_("[OD] ERROR: Dobby syms"); return; }

    void* hCLEO = dlopen("libCLEO.so", RTLD_NOW | RTLD_NOLOAD);
    if (!hCLEO) hCLEO = dlopen("libCLEO.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hCLEO) { logf_("[OD] ERROR: libCLEO"); return; }

    // Simpan pointer ScriptSpace untuk do_scan
    void* pSpace = resolver("libCLEO.so", "_ZN11CTheScripts11ScriptSpaceE");
    if (!pSpace) pSpace = dlsym(hCLEO, "_ZN11CTheScripts11ScriptSpaceE");
    if (!pSpace) { logf_("[OD] ERROR: ScriptSpace"); return; }
    g_scriptspace = (uint8_t*)pSpace;
    logff_("[OD] ScriptSpace=%p", g_scriptspace);

    // Hook LoadAllScripts
    void* addrLoad = resolver("libCLEO.so", "_ZN11CTheScripts14LoadAllScriptsEPhj");
    if (!addrLoad) addrLoad = dlsym(hCLEO, "_ZN11CTheScripts14LoadAllScriptsEPhj");
    if (!addrLoad) { logf_("[OD] ERROR: LoadAllScripts tidak ditemukan"); return; }
    logff_("[OD] LoadAllScripts addr=%p", addrLoad);

    int ret = dobbyHook(addrLoad, (void*)hook_LoadAllScripts, (void**)&orig_LoadAllScripts);
    logff_("[OD] DobbyHook ret=%d orig=%p", ret, orig_LoadAllScripts);
    if (ret != 0 || !orig_LoadAllScripts) {
        logf_("[OD] ERROR: hook gagal"); return;
    }

    logf_("[OD] Hook terpasang, menunggu LoadAllScripts...");
}

} // extern "C"
