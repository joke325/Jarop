/**
 * Copyright (c) 2020 Janky <box@janky.tech>
 * All right reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif

void ThrowMissingLibrary(const char* libName, const char* err);
void ThrowMissingMethod(const char* metName, const char* err);

#if defined(_WIN32) && defined(_MSC_VER)
    #include <stdio.h>
    #include <Windows.h>
    #define ROP_LIB_NAME "librnp-0.dll"
    static HMODULE hlib = NULL;

    void on_attach() {
        hlib = LoadLibrary(TEXT(ROP_LIB_NAME));
        if (hlib == NULL) {
            char buf[0x20]; snprintf(buf, sizeof(buf), "Error %08X", GetLastError());
            ThrowMissingLibrary(ROP_LIB_NAME, buf);
        }
    }

    void on_detach() { if (hlib != NULL) FreeLibrary(hlib); hlib = NULL; }

    static void* RopDlSym(const char* symbol) {
        if (hlib != NULL) {
            void* ptr = GetProcAddress(hlib, symbol);
            if (ptr == NULL) {
                char buf[0x20]; snprintf(buf, sizeof(buf), "Error %08X", GetLastError());
                ThrowMissingMethod(symbol, buf);
            }
            return ptr;
        }
        return NULL;
    }

    BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
        switch (reason) {
        case DLL_PROCESS_ATTACH: /*on_attach();*/ break;
        case DLL_PROCESS_DETACH: on_detach();  break;
        }
        return TRUE;
    }

#else

    #include <dlfcn.h>
    #define ROP_LIB_NAME "librnp-0.so"
    static void *hlib = NULL;

    //__attribute__((constructor))
    void on_attach() { 
        hlib = dlopen(ROP_LIB_NAME, RTLD_LAZY); 
        if(hlib==NULL) ThrowMissingLibrary(ROP_LIB_NAME, dlerror()); 
    }

    __attribute__((destructor))
    void on_detach() { if(hlib != NULL) dlclose(hlib); hlib = NULL; }

    static void* RopDlSym(const char *symbol) {
        if(hlib != NULL) {
            void *ptr = dlsym(hlib, symbol);
            if(ptr == NULL)
                ThrowMissingMethod(symbol, dlerror());
            return ptr;
        }
        return NULL;
    }

#endif

#define ROP_FFI_DEF_FX(rtype, symb, alist) \
    rtype(*p##symb) alist = NULL; \
    rtype symb

#define ROP_FFI_LOAD_SYMBOL(symb, lsymb) \
    if(p##symb == NULL) \
        p##symb = RopDlSym(#lsymb)

#define ROP_DYN_IMPORT(rtype, rdefl, fname, sname, alist, plist) \
    ROP_FFI_DEF_FX(rtype, fname, alist) alist { \
        ROP_FFI_LOAD_SYMBOL(fname, sname); \
        return p##fname!=NULL? p##fname plist : rdefl; \
    }

#define FX
#define FP0 ()
#define FA0 ()
#define FP1 FX(a)
#define FA1(t1) FX(t1 a)
#define FP2 FX(a, b)
#define FA2(t1, t2) FX(t1 a, t2 b)
#define FP3 FX(a, b, c)
#define FA3(t1, t2, t3) FX(t1 a, t2 b, t3 c)
#define FP4 FX(a, b, c, d)
#define FA4(t1, t2, t3, t4) FX(t1 a, t2 b, t3 c, t4 d)
#define FP5 FX(a, b, c, d, e)
#define FA5(t1, t2, t3, t4, t5) FX(t1 a, t2 b, t3 c, t4 d, t5 e)
#define FP6 FX(a, b, c, d, e, f)
#define FA6(t1, t2, t3, t4, t5, t6) FX(t1 a, t2 b, t3 c, t4 d, t5 e, t6 f)
#define FP10 FX(a, b, c, d, e, f, g, h, i, j)
#define FA10(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10) FX(t1 a, t2 b, t3 c, t4 d, t5 e, t6 f, t7 g, t8 h, t9 i, t10 j)

#define ROP_DYN_IMP0(r, d, n, s) ROP_DYN_IMPORT(r, d, n, s, FA0, FP0)
#define ROP_DYN_IMP1(r, d, n, s, p1) ROP_DYN_IMPORT(r, d, n, s, FA1(p1), FP1)
#define ROP_DYN_IMP2(r, d, n, s, p1, p2) ROP_DYN_IMPORT(r, d, n, s, FA2(p1, p2), FP2)
#define ROP_DYN_IMP3(r, d, n, s, p1, p2, p3) ROP_DYN_IMPORT(r, d, n, s, FA3(p1, p2, p3), FP3)
#define ROP_DYN_IMP4(r, d, n, s, p1, p2, p3, p4) ROP_DYN_IMPORT(r, d, n, s, FA4(p1, p2, p3, p4), FP4)
#define ROP_DYN_IMP5(r, d, n, s, p1, p2, p3, p4, p5) ROP_DYN_IMPORT(r, d, n, s, FA5(p1, p2, p3, p4, p5), FP5)
#define ROP_DYN_IMP6(r, d, n, s, p1, p2, p3, p4, p5, p6) ROP_DYN_IMPORT(r, d, n, s, FA6(p1, p2, p3, p4, p5, p6), FP6)
#define ROP_DYN_IMP10(r, d, n, s, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10) ROP_DYN_IMPORT(r, d, n, s, FA10(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10), FP10)

#define ROP_DYN_IMPORT0(r, d, n) ROP_DYN_IMP0(r, d, dlF(n), n)
#define ROP_DYN_IMPORT1(r, d, n, p1) ROP_DYN_IMP1(r, d, dlF(n), n, p1)
#define ROP_DYN_IMPORT2(r, d, n, p1, p2) ROP_DYN_IMP2(r, d, dlF(n), n, p1, p2)
#define ROP_DYN_IMPORT3(r, d, n, p1, p2, p3) ROP_DYN_IMP3(r, d, dlF(n), n, p1, p2, p3)
#define ROP_DYN_IMPORT4(r, d, n, p1, p2, p3, p4) ROP_DYN_IMP4(r, d, dlF(n), n, p1, p2, p3, p4)
#define ROP_DYN_IMPORT5(r, d, n, p1, p2, p3, p4, p5) ROP_DYN_IMP5(r, d, dlF(n), n, p1, p2, p3, p4, p5)
#define ROP_DYN_IMPORT6(r, d, n, p1, p2, p3, p4, p5, p6) ROP_DYN_IMP6(r, d, dlF(n), n, p1, p2, p3, p4, p5, p6)
#define ROP_DYN_IMPORT10(r, d, n, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10) ROP_DYN_IMP10(r, d, dlF(n), n, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)


#include "load.h"


#ifdef __cplusplus
}
#endif
