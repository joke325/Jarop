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

/**
 * @version 0.3.0
 */

#include <stdlib.h>
#include <string.h>
#include <jni.h>
#include "load.h"

#ifdef __cplusplus
extern "C" {
#endif
    
static void key_callback(rnp_ffi_t ffi, void *app_ctx, const char *identifier_type, const char *identifier, bool secret);
static bool pass_callback(rnp_ffi_t ffi, void *app_ctx, rnp_key_handle_t key, const char *pgp_context, char buf[], size_t buf_len);
static bool input_read_callback(void *app_ctx, void *buf, size_t len, size_t *read);
static void input_close_callback(void *app_ctx);
static bool output_write_callback(void *app_ctx, const void *buf, size_t len);
static void output_close_callback(void *app_ctx, bool discard);
    

static JavaVM *jvm = NULL;
static jint jniVer = JNI_VERSION_1_8;

static jint AttachToVM(JNIEnv **jenv) {
    *jenv = NULL;
    jint jeStat = (*jvm)->GetEnv(jvm, (void**)jenv, jniVer);
    if(jeStat == JNI_EDETACHED) {
        (*jvm)->AttachCurrentThread(jvm, (void**)jenv, NULL);
    }
    return jeStat;
}

static void DettachFromVM(JNIEnv *jenv, jint jeStat) {
    if(jeStat == JNI_EDETACHED) {
        (*jvm)->DetachCurrentThread(jvm);
    }
}

static jmethodID FindJMethod(JNIEnv *jenv, jobject obj, const char*const *methodIds, jclass* clsObj) {
    jclass cls = (clsObj!=NULL? *clsObj : NULL);
    if(cls == NULL) {
        if(obj != NULL)
            cls = (*jenv)->GetObjectClass(jenv, obj);
        else if(methodIds[2] != NULL)
            cls = (*jenv)->FindClass(jenv, methodIds[2]);
    }
    if(clsObj != NULL)
        *clsObj = cls;
    return cls!=NULL? (*jenv)->GetMethodID(jenv, cls, methodIds[0], methodIds[1]) : NULL;
}

static jfieldID FindJField(JNIEnv* jenv, jobject obj, const char* const* fieldIds, jclass* clsObj) {
    jclass cls = (clsObj != NULL ? *clsObj : NULL);
    if (cls == NULL) {
        if (obj != NULL)
            cls = (*jenv)->GetObjectClass(jenv, obj);
        else if (fieldIds[2] != NULL)
            cls = (*jenv)->FindClass(jenv, fieldIds[2]);
    }
    if (clsObj != NULL)
        *clsObj = cls;
    return cls!=NULL? (*jenv)->GetFieldID(jenv, cls, fieldIds[0], fieldIds[1]) : NULL;
}


static jobject AddObject(JNIEnv *jenv, jobject output, jobject value) {
    jobject out = NULL;
    if(output != NULL) {
        const char *metId[] = { "add", "(Ljava/lang/Object;)Z", NULL };
        jmethodID addMid = FindJMethod(jenv, output, metId, NULL);
        out = (addMid!=NULL && (*jenv)->CallBooleanMethod(jenv, output, addMid, value))? value : NULL;
    }
    return out;
}

static jobject AddTHandle(JNIEnv *jenv, jobject output, const void *ptr, int type) {
    jobject hndObj = NULL;
    jclass hndCls = NULL;
    const char* metId[] = { "<init>", "(IZ[B)V", "tech/janky/jarop/rop/RopHandle" };
    jmethodID hndMid = FindJMethod(jenv, NULL, metId, &hndCls);
    jobject hndData = (hndMid!=NULL? (*jenv)->NewByteArray(jenv, sizeof(ptr)) : NULL);
    if (hndData != NULL) {
        const void *cd[] = { ptr };
        (*jenv)->SetByteArrayRegion(jenv, hndData, 0, sizeof(ptr), (jbyte*)(cd+0));
        if((*jenv)->ExceptionCheck(jenv) == JNI_FALSE)
            hndObj = (*jenv)->NewObject(jenv, hndCls, hndMid, type, ptr==NULL, hndData);
        if(hndObj != NULL && output != NULL)
            hndObj = AddObject(jenv, output, hndObj);
    }
    return hndObj;
}

static jobject AddHandle(JNIEnv *jenv, jobject output, const void *ptr) {
    return AddTHandle(jenv, output, ptr, 0);
}

static jobject AddStrHandle(JNIEnv *jenv, jobject output, const char* ptr) {
    return AddTHandle(jenv, output, ptr, 1);
}

void* Handle2PtrT(JNIEnv *jenv, jobject handle, int* type) {
    void *ptr = NULL;
    if(handle != NULL) {
        jclass hndCls = NULL;
        const char* fldId[] = { "data", "[B", "tech/janky/jarop/rop/RopHandle" };
        jfieldID hndFid = FindJField(jenv, NULL, fldId, &hndCls);
        jobject hndData = (hndFid!=NULL? (*jenv)->GetObjectField(jenv, handle, hndFid) : NULL);
        if(hndData != NULL) {
            (*jenv)->GetByteArrayRegion(jenv, hndData, 0, sizeof(ptr), (jbyte*)&ptr);
            if(type != NULL && (*jenv)->ExceptionCheck(jenv) == JNI_FALSE) {
                fldId[0] = "type", fldId[1] = "I";
                hndFid = FindJField(jenv, NULL, fldId, &hndCls);
                if(hndFid != NULL) {
                    jint hndType = (*jenv)->GetIntField(jenv, handle, hndFid);
                    if((*jenv)->ExceptionCheck(jenv) == JNI_FALSE)
                    *type = hndType;
                }
            }
        }
    }
    return ptr;
}

static void* Handle2Ptr(JNIEnv *jenv, jobject handle) {
    return Handle2PtrT(jenv, handle, NULL);
}

static bool AddInteger(JNIEnv *jenv, jobject output, jint value) {
    jclass intCls = NULL;
    const char* metId[] = { "<init>", "(I)V", "Ljava/lang/Integer;" };
    jmethodID intMid = FindJMethod(jenv, NULL, metId, &intCls);
    if(intMid != NULL) {
        jobject intObj = (*jenv)->NewObject(jenv, intCls, intMid, value);
        if(intObj != NULL)
            return AddObject(jenv, output, intObj) != NULL;
    }
    return false;
}

static bool AddLong(JNIEnv *jenv, jobject output, jlong value) {
    jclass lngCls = NULL;
    const char* metId[] = { "<init>", "(J)V", "Ljava/lang/Long;" };
    jmethodID lngMid = FindJMethod(jenv, NULL, metId, &lngCls);
    if(lngMid != NULL) {
        jobject lngObj = (*jenv)->NewObject(jenv, lngCls, lngMid, value);
        if(lngObj != NULL)
            return AddObject(jenv, output, lngObj);
    }
    return false;
}

static bool AddBoolean(JNIEnv *jenv, jobject output, bool value) {
    return AddInteger(jenv, output, value? JNI_TRUE : JNI_FALSE);
}

static const char* EncodeString(JNIEnv *jenv, jobject jstr, int* sctx) {
    const char *str = NULL;
    *sctx = 0;
    if((*jenv)->IsInstanceOf(jenv, jstr, (*jenv)->FindClass(jenv, "Ljava/lang/String;"))) {
        *sctx = 1;
        str = (jstr!=NULL? (*jenv)->GetStringUTFChars(jenv, jstr, NULL) : NULL);
    } else {
        if((*jenv)->IsInstanceOf(jenv, jstr, (*jenv)->FindClass(jenv, "[B"))) {
            *sctx = 2;
            jsize alen = (*jenv)->GetArrayLength(jenv, jstr);
            if((*jenv)->ExceptionCheck(jenv) == JNI_FALSE) {
                char* cstr = malloc(alen + 1);
                (*jenv)->GetByteArrayRegion(jenv, jstr, 0, alen, cstr);
                cstr[alen] = '\0';
                if((*jenv)->ExceptionCheck(jenv) == JNI_FALSE)
                    str = cstr;
                else
                    free(cstr);
            }
        } else
            str = (char*)Handle2Ptr(jenv, jstr);
    }
    return str;
}

static void EncodeFree(JNIEnv *jenv, jobject jstr, const char* cstr, int sctx) {
    if(cstr != NULL)
        switch(sctx) {
        case 1:
            (*jenv)->ReleaseStringUTFChars(jenv, jstr, cstr);
            break;
        case 2:
            free((char*)cstr);
            break;
        }
}

void SetHandle(JNIEnv *jenv, jobject rmap, jobject key, jobject value) {
    jclass clsMap = NULL;
    const char* metId[] = { "remove", "(Ljava/lang/Object;)Ljava/lang/Object;", NULL };
    jmethodID midRem = FindJMethod(jenv, rmap, metId, &clsMap);

    jobject currVal = (midRem!=NULL? (*jenv)->CallObjectMethod(jenv, rmap, midRem, key) : NULL);
    if(currVal != NULL) {
        jclass clsVal = NULL;
        const char* fldId[] = { "source", "Ljava/lang/Object;", NULL };
        jfieldID fidSrc = FindJField(jenv, currVal, fldId, &clsVal);
        jobject source = (fidSrc!=NULL? (*jenv)->GetObjectField(jenv, currVal, fidSrc) : NULL);
        if((*jenv)->ExceptionCheck(jenv) == JNI_FALSE) {
            jfieldID fidSI = (*jenv)->GetFieldID(jenv, clsVal, "src_i", "I");
            if(fidSI != NULL) {
                jint si = (*jenv)->GetIntField(jenv, currVal, fidSI);
                if((*jenv)->ExceptionCheck(jenv) == JNI_FALSE) {
                    void *ptr = Handle2Ptr(jenv, currVal);
                    EncodeFree(jenv, source, ptr, si);
                }
            }
        }
    }
    if(value != NULL) {
        jmethodID midPut = (*jenv)->GetMethodID(jenv, clsMap, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
        if(midPut != NULL)
            currVal = (*jenv)->CallObjectMethod(jenv, rmap, midPut, key, value);
    }
}


#define ENCODE_PROLOG(_cnt) int _sctx[_cnt], _sidx=0
#define ENCODE_STRING(_nm) const char *c##_nm = EncodeString(jenv, _nm, _sctx+(_sidx++))
#define ENCODE_1STRING(_nm1) ENCODE_PROLOG(1); ENCODE_STRING(_nm1)
#define ENCODE_2STRINGS(_nm1, _nm2) ENCODE_PROLOG(2); ENCODE_STRING(_nm1); ENCODE_STRING(_nm2)
#define ENCODE_NEXT3STRINGS(_nm1, _nm2, _nm3) ENCODE_STRING(_nm1); ENCODE_STRING(_nm2); ENCODE_STRING(_nm3)
#define ENCODE_3STRINGS(_nm1, _nm2, _nm3) ENCODE_PROLOG(3); ENCODE_NEXT3STRINGS(_nm1, _nm2, _nm3)
#define ENCODE_FREE(_nm) EncodeFree(jenv, _nm, c##_nm, _sctx[--_sidx])
#define ENCODE_FREE2(_nm1, _nm2) ENCODE_FREE(_nm2); ENCODE_FREE(_nm1)
#define ENCODE_FREE3(_nm1, _nm2, _nm3) ENCODE_FREE(_nm3); ENCODE_FREE(_nm2); ENCODE_FREE(_nm1)
#define CPTR(_var) (_var!=NULL? &(c##_var) : NULL)

JNIEXPORT jstring JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1result_1to_1string(JNIEnv *jenv, jobject jobj, jint result) {
    const char *ret = dlF(rnp_result_to_string)(result);
    return ret!=NULL? (*jenv)->NewStringUTF(jenv, ret) : NULL;    
}

JNIEXPORT jstring JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1version_1string(JNIEnv *jenv, jobject jobj) {
    const char *ret = dlF(rnp_version_string)();
    return ret!=NULL? (*jenv)->NewStringUTF(jenv, ret) : NULL;    
}

JNIEXPORT jstring JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1version_1string_1full(JNIEnv *jenv, jobject jobj) {
    const char *ret = dlF(rnp_version_string_full)();
    return ret!=NULL? (*jenv)->NewStringUTF(jenv, ret) : NULL;
}

JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1version(JNIEnv *jenv, jobject jobj) {
    return dlF(rnp_version)();
}

JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1version_1for(JNIEnv *jenv, jobject jobj, jint major, jint minor, jint patch) {
    return dlF(rnp_version_for)(major, minor, patch);
}

JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1version_1major(JNIEnv *jenv, jobject jobj, jint version) {
    return dlF(rnp_version_major)(version);
}

JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1version_1minor(JNIEnv *jenv, jobject jobj, jint version) {
    return dlF(rnp_version_minor)(version);
}

JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1version_1patch(JNIEnv *jenv, jobject jobj, jint version) {
    return dlF(rnp_version_patch)(version);
}

JNIEXPORT jlong JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1version_1commit_1timestamp(JNIEnv *jenv, jobject jobj) {
    return dlF(rnp_version_commit_timestamp)();
}

JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1enable_1debug(JNIEnv *jenv, jobject jobj, jstring file) {
    ENCODE_1STRING(file);
    rnp_result_t ret = dlF(rnp_enable_debug)(cfile);
    ENCODE_FREE(file);
    return ret;
}

JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1disable_1debug(JNIEnv *jenv, jobject jobj) {
    return dlF(rnp_disable_debug)();
}

//F(ffi: [cd], pub_format: str, sec_format: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1ffi_1create(JNIEnv *jenv, jobject jobj, jobject ffi, jstring pub_format, jstring sec_format) {
    rnp_ffi_t cffi = NULL;
    ENCODE_2STRINGS(pub_format, sec_format);
    rnp_result_t ret = dlF(rnp_ffi_create)(CPTR(ffi), cpub_format, csec_format);
    ENCODE_FREE2(pub_format, sec_format);
    AddHandle(jenv, ffi, cffi);
    return ret;
}

//F(ffi: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_nrnp_1ffi_1destroy(JNIEnv *jenv, jobject jobj, jobject ffi) {
    void *cffi = Handle2Ptr(jenv, ffi);
    return dlF(rnp_ffi_destroy)(cffi);
}

//F(ffi: cd, fd_: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1ffi_1set_1log_1fd(JNIEnv *jenv, jobject jobj, jobject ffi, jint fd) {
    void *cffi = Handle2Ptr(jenv, ffi);
    return dlF(rnp_ffi_set_log_fd)(cffi, fd);
}

//F(ffi: cd, getkeycb: Rop_get_key_cb, getkeycb_ctx: obj) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_nrnp_1ffi_1set_1key_1provider(JNIEnv *jenv, jobject jobj, jobject ffi, jobject gref) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cgref = Handle2Ptr(jenv, gref);
    return dlF(rnp_ffi_set_key_provider)(cffi, key_callback, cgref);
}

//F(ffi: cd, getpasscb: Rop_password_cb, getpasscb_ctx: obj) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_nrnp_1ffi_1set_1pass_1provider(JNIEnv *jenv, jobject jobj, jobject ffi, jobject gref) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cgref = Handle2Ptr(jenv, gref);
    return dlF(rnp_ffi_set_pass_provider)(cffi, pass_callback, cgref);
}

//F(homedir: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1get_1default_1homedir(JNIEnv *jenv, jobject jobj, jobject homedir) {
    char *chomedir = NULL;
    rnp_result_t ret = dlF(rnp_get_default_homedir)(CPTR(homedir));
    AddStrHandle(jenv, homedir, chomedir);
    return ret;
}

//F(homedir: str, pub_format: [cd], pub_path: [cd], sec_format: [cd], sec_path: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1detect_1homedir_1info(JNIEnv *jenv, jobject jobj, jobject homedir, jobject pub_format, jobject pub_path, jobject sec_format, jobject sec_path) {
    char *ptrs[] = { NULL, NULL, NULL, NULL };
    ENCODE_1STRING(homedir);
    rnp_result_t ret = dlF(rnp_detect_homedir_info)(chomedir, ptrs+0, ptrs+1, ptrs+2, ptrs+3);
    ENCODE_FREE(homedir);
    AddStrHandle(jenv, pub_format, ptrs[0]);
    AddStrHandle(jenv, pub_path, ptrs[1]);
    AddStrHandle(jenv, sec_format, ptrs[2]);
    AddStrHandle(jenv, sec_path, ptrs[3]);
    return ret;
}

//F(buf: str, buf_len: int, format_: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1detect_1key_1format(JNIEnv *jenv, jobject jobj, jobject buf, jsize buf_len, jobject format) {
    ENCODE_1STRING(buf);
    char *cformat = NULL;
    rnp_result_t ret = dlF(rnp_detect_key_format)((const uint8_t*)cbuf, buf_len, CPTR(format));
    ENCODE_FREE(buf);
    AddStrHandle(jenv, format, cformat);
    return ret;
}

//F(hash_: str, msec: int, iterations: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1calculate_1iterations(JNIEnv *jenv, jobject jobj, jobject hash, jsize msec, jobject iterations) {
    ENCODE_1STRING(hash);
    size_t citerations = 0;
    rnp_result_t ret = dlF(rnp_calculate_iterations)(chash, msec, CPTR(iterations));
    ENCODE_FREE(hash);
    AddInteger(jenv, iterations, (jint)citerations);
    return ret;
}

//F(type_: str, name: str, supported: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1supports_1feature(JNIEnv *jenv, jobject jobj, jobject type, jobject name, jobject supported) {
    ENCODE_2STRINGS(type, name);
    bool csupported = false;
    rnp_result_t ret = dlF(rnp_supports_feature)(ctype, cname, CPTR(supported));
    ENCODE_FREE2(type, name);
    AddBoolean(jenv, supported, csupported);
    return ret;
}

//F(type_: str, result: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1supported_1features(JNIEnv *jenv, jobject jobj, jobject type, jobject result) {
    ENCODE_1STRING(type);
    char *cresult = NULL;
    rnp_result_t ret = dlF(rnp_supported_features)(ctype, CPTR(result));
    ENCODE_FREE(type);
    AddStrHandle(jenv, result, cresult);
    return ret;
}

//F(ffi: cd, key: cd, context: str, password: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1request_1password(JNIEnv *jenv, jobject jobj, jobject ffi, jobject key, jobject context, jobject password) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *ckey = Handle2Ptr(jenv, key);
    ENCODE_1STRING(context);
    char *cpassword = NULL;
    rnp_result_t ret = dlF(rnp_request_password)(cffi, ckey, ccontext, CPTR(password));
    AddStrHandle(jenv, password, cpassword);
    ENCODE_FREE(context);
    return ret;
}

//F(ffi: cd, format_: str, input_: cd, flags: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1load_1keys(JNIEnv *jenv, jobject jobj, jobject ffi, jobject format, jobject input, jint flags) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_1STRING(format);
    void *cinput = Handle2Ptr(jenv, input);
    rnp_result_t ret = dlF(rnp_load_keys)(cffi, cformat, cinput, flags);
    ENCODE_FREE(format);
    return ret;
}

//F(ffi: cd, flags: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1unload_1keys(JNIEnv *jenv, jobject jobj, jobject ffi, jint flags) {
    void *cffi = Handle2Ptr(jenv, ffi);
    return dlF(rnp_unload_keys)(cffi, flags);
}

//F(ffi: cd, input_: cd, flags: int, results: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1import_1keys(JNIEnv *jenv, jobject jobj, jobject ffi, jobject input, jint flags, jobject results) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cinput = Handle2Ptr(jenv, input);
    char *cresults = NULL;
    rnp_result_t ret = dlF(rnp_import_keys)(cffi, cinput, flags, CPTR(results));
    AddStrHandle(jenv, results, cresults);
    return ret;
}

JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1import_1signatures(JNIEnv *jenv, jobject jobj, jobject ffi, jobject input, jint flags, jobject results) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cinput = Handle2Ptr(jenv, input);
    char *cresults = NULL;
    rnp_result_t ret = dlF(rnp_import_signatures)(cffi, cinput, flags, CPTR(results));
    AddStrHandle(jenv, results, cresults);
    return ret;
}

//F(ffi: cd, format_: str, output: cd, flags: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1save_1keys(JNIEnv *jenv, jobject jobj, jobject ffi, jobject format, jobject output, jint flags) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_1STRING(format);
    void *coutput = Handle2Ptr(jenv, output);
    rnp_result_t ret = dlF(rnp_save_keys)(cffi, cformat, coutput, flags);
    ENCODE_FREE(format);
    return ret;
}

//F(ffi: cd, count: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1get_1public_1key_1count(JNIEnv *jenv, jobject jobj, jobject ffi, jobject count) {
    void *cffi = Handle2Ptr(jenv, ffi);
    size_t ccount = 0;
    rnp_result_t ret = dlF(rnp_get_public_key_count)(cffi, CPTR(count));
    AddInteger(jenv, count, (jint)ccount);
    return ret;
}

//F(ffi: cd, count: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1get_1secret_1key_1count(JNIEnv *jenv, jobject jobj, jobject ffi, jobject count) {
    void *cffi = Handle2Ptr(jenv, ffi);
    size_t ccount = 0;
    rnp_result_t ret = dlF(rnp_get_secret_key_count)(cffi, CPTR(count));
    AddInteger(jenv, count, (jint)ccount);
    return ret;
}

//F(ffi: cd, identifier_type: str, identifier: str, key: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1locate_1key(JNIEnv *jenv, jobject jobj, jobject ffi, jobject identifier_type, jobject identifier, jobject key) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_2STRINGS(identifier_type, identifier);
    rnp_key_handle_t ckey = NULL;
    rnp_result_t ret = dlF(rnp_locate_key)(cffi, cidentifier_type, cidentifier, CPTR(key));
    ENCODE_FREE2(identifier_type, identifier);
    AddHandle(jenv, key, ckey);
    return ret;
}

//F(key: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1handle_1destroy(JNIEnv *jenv, jobject jobj, jobject key) {
    void *ckey = Handle2Ptr(jenv, key);
    return dlF(rnp_key_handle_destroy)(ckey);
}

//F(ffi: cd, json: str, results: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1generate_1key_1json(JNIEnv *jenv, jobject jobj, jobject ffi, jobject json, jobject results) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_1STRING(json);
    char *cresults = NULL;
    rnp_result_t ret = dlF(rnp_generate_key_json)(cffi, cjson, CPTR(results));
    ENCODE_FREE(json);
    AddStrHandle(jenv, results, cresults);
    return ret;
}

//F(ffi: cd, bits: int, subbits: int, userid: str, password: str, key: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1generate_1key_1rsa(JNIEnv *jenv, jobject jobj, jobject ffi, jint bits, jint subbits, jobject userid, jobject password, jobject key) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_2STRINGS(userid, password);
    rnp_key_handle_t ckey = NULL;
    rnp_result_t ret = dlF(rnp_generate_key_rsa)(cffi, bits, subbits, cuserid, cpassword, CPTR(key));
    ENCODE_FREE2(userid, password);
    AddHandle(jenv, key, ckey);
    return ret;
}

//F(ffi: cd, bits: int, subbits: int, userid: str, password: str, key: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1generate_1key_1dsa_1eg(JNIEnv *jenv, jobject jobj, jobject ffi, jint bits, jint subbits, jobject userid, jobject password, jobject key) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_2STRINGS(userid, password);
    rnp_key_handle_t ckey = NULL;
    rnp_result_t ret = dlF(rnp_generate_key_dsa_eg)(cffi, bits, subbits, cuserid, cpassword, CPTR(key));
    ENCODE_FREE2(userid, password);
    AddHandle(jenv, key, ckey);
    return ret;
}

//F(ffi: cd, curve: str, userid: str, password: str, key: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1generate_1key_1ec(JNIEnv *jenv, jobject jobj, jobject ffi, jobject curve, jobject userid, jobject password, jobject key) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_3STRINGS(curve, userid, password);
    rnp_key_handle_t ckey = NULL;
    rnp_result_t ret = dlF(rnp_generate_key_ec)(cffi, ccurve, cuserid, cpassword, CPTR(key));
    ENCODE_FREE3(curve, userid, password);
    AddHandle(jenv, key, ckey);
    return ret;
}

//F(ffi: cd, userid: str, password: str, key: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1generate_1key_125519(JNIEnv *jenv, jobject jobj, jobject ffi, jobject userid, jobject password, jobject key) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_2STRINGS(userid, password);
    rnp_key_handle_t ckey = NULL;
    rnp_result_t ret = dlF(rnp_generate_key_25519)(cffi, cuserid, cpassword, CPTR(key));
    ENCODE_FREE2(userid, password);
    AddHandle(jenv, key, ckey);
    return ret;
}

//F(ffi: cd, userid: str, password: str, key: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1generate_1key_1sm2(JNIEnv *jenv, jobject jobj, jobject ffi, jobject userid, jobject password, jobject key) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_2STRINGS(userid, password);
    rnp_key_handle_t ckey = NULL;
    rnp_result_t ret = dlF(rnp_generate_key_sm2)(cffi, cuserid, cpassword, CPTR(key));
    ENCODE_FREE2(userid, password);
    AddHandle(jenv, key, ckey);
    return ret;
}

//F(ffi: cd, key_alg: str, sub_alg: str, key_bits: int, sub_bits: int, key_curve: str, sub_curve: str, userid: str, password: str, key: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1generate_1key_1ex(JNIEnv *jenv, jobject jobj, jobject ffi, jobject key_alg, jobject sub_alg, jint key_bits, jint sub_bits, jobject key_curve, jobject sub_curve, jobject userid, jobject password, jobject key) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_PROLOG(6);
    ENCODE_NEXT3STRINGS(key_alg, sub_alg, key_curve);
    ENCODE_NEXT3STRINGS(sub_curve, userid, password);
    rnp_key_handle_t ckey = NULL;
    rnp_result_t ret = dlF(rnp_generate_key_ex)(cffi, ckey_alg, csub_alg, key_bits, sub_bits, ckey_curve, csub_curve, cuserid, cpassword, CPTR(key));
    ENCODE_FREE3(sub_curve, userid, password);
    ENCODE_FREE3(key_alg, sub_alg, key_curve);
    AddHandle(jenv, key, ckey);
    return ret;
}

//F(op_: [cd], ffi: cd, alg: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1create(JNIEnv *jenv, jobject jobj, jobject op, jobject ffi, jobject alg) {
    void *cffi = Handle2Ptr(jenv, ffi);
    ENCODE_1STRING(alg);
    rnp_op_generate_t cop = NULL;
    rnp_result_t ret = dlF(rnp_op_generate_create)(CPTR(op), cffi, calg);
    ENCODE_FREE(alg);
    AddHandle(jenv, op, cop);
    return ret;
}

//F(op_: [cd], ffi: cd, primary: cd, alg: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1subkey_1create(JNIEnv *jenv, jobject jobj, jobject op, jobject ffi, jobject primary, jobject alg) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cprimary = Handle2Ptr(jenv, primary);
    ENCODE_1STRING(alg);
    rnp_op_generate_t cop = NULL;
    rnp_result_t ret = dlF(rnp_op_generate_subkey_create)(CPTR(op), cffi, cprimary, calg);
    ENCODE_FREE(alg);
    AddHandle(jenv, op, cop);
    return ret;
}

//F(op_: cd, bits: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1bits(JNIEnv *jenv, jobject jobj, jobject op, jint bits) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_set_bits)(cop, bits);
}

//F(op_: cd, hash_: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1hash(JNIEnv *jenv, jobject jobj, jobject op, jobject hash) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(hash);
    rnp_result_t ret = dlF(rnp_op_generate_set_hash)(cop, chash);
    ENCODE_FREE(hash);
    return ret;
}

//F(op_: cd, qbits: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1dsa_1qbits(JNIEnv *jenv, jobject jobj, jobject op, jint qbits) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_set_dsa_qbits)(cop, qbits);
}

//F(op_: cd, curve: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1curve(JNIEnv *jenv, jobject jobj, jobject op, jobject curve) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(curve);
    rnp_result_t ret = dlF(rnp_op_generate_set_curve)(cop, ccurve);
    ENCODE_FREE(curve);
    return ret;
}

//F(op_: cd, password: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1protection_1password(JNIEnv *jenv, jobject jobj, jobject op, jobject password) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(password);
    rnp_result_t ret = dlF(rnp_op_generate_set_protection_password)(cop, cpassword);
    ENCODE_FREE(password);
    return ret;
}

//F(op_: cd, request: bool) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1request_1password(JNIEnv *jenv, jobject jobj, jobject op, jboolean request) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_set_request_password)(cop, request);
}

//F(op_: cd, cipher: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1protection_1cipher(JNIEnv *jenv, jobject jobj, jobject op, jobject cipher) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(cipher);
    rnp_result_t ret = dlF(rnp_op_generate_set_protection_cipher)(cop, ccipher);
    ENCODE_FREE(cipher);
    return ret;
}

//F(op_: cd, hash_: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1protection_1hash(JNIEnv *jenv, jobject jobj, jobject op, jobject hash) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(hash);
    rnp_result_t ret = dlF(rnp_op_generate_set_protection_hash)(cop, chash);
    ENCODE_FREE(hash);
    return ret;
}

//F(op_: cd, mode: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1protection_1mode(JNIEnv *jenv, jobject jobj, jobject op, jobject mode) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(mode);
    rnp_result_t ret = dlF(rnp_op_generate_set_protection_mode)(cop, cmode);
    ENCODE_FREE(mode);
    return ret;
}

//F(op_: cd, iterations: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1protection_1iterations(JNIEnv *jenv, jobject jobj, jobject op, jint iterations) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_set_protection_iterations)(cop, iterations);
}

//F(op_: cd, usage: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1add_1usage(JNIEnv *jenv, jobject jobj, jobject op, jobject usage) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(usage);
    rnp_result_t ret = dlF(rnp_op_generate_add_usage)(cop, cusage);
    ENCODE_FREE(usage);
    return ret;
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1clear_1usage(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_clear_usage)(cop);
}

//F(op_: cd, userid: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1userid(JNIEnv *jenv, jobject jobj, jobject op, jobject userid) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(userid);
    rnp_result_t ret = dlF(rnp_op_generate_set_userid)(cop, cuserid);
    ENCODE_FREE(userid);
    return ret;
}

//F(op_: cd, expiration: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1expiration(JNIEnv *jenv, jobject jobj, jobject op, jlong expiration) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_set_expiration)(cop, (uint32_t)expiration);
}

//F(op_: cd, hash_: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1add_1pref_1hash(JNIEnv *jenv, jobject jobj, jobject op, jobject hash) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(hash);
    rnp_result_t ret = dlF(rnp_op_generate_add_pref_hash)(cop, chash);
    ENCODE_FREE(hash);
    return ret;
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1clear_1pref_1hashes(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_clear_pref_hashes)(cop);
}

//F(op_: cd, compression: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1add_1pref_1compression(JNIEnv *jenv, jobject jobj, jobject op, jobject compression) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(compression);
    rnp_result_t ret = dlF(rnp_op_generate_add_pref_compression)(cop, ccompression);
    ENCODE_FREE(compression);
    return ret;
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1clear_1pref_1compression(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_clear_pref_compression)(cop);
}

//F(op_: cd, cipher: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1add_1pref_1cipher(JNIEnv *jenv, jobject jobj, jobject op, jobject cipher) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(cipher);
    rnp_result_t ret = dlF(rnp_op_generate_add_pref_cipher)(cop, ccipher);
    ENCODE_FREE(cipher);
    return ret;
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1clear_1pref_1ciphers(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_clear_pref_ciphers)(cop);
}

//F(op_: cd, keyserver: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1set_1pref_1keyserver(JNIEnv *jenv, jobject jobj, jobject op, jobject keyserver) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(keyserver);
    rnp_result_t ret = dlF(rnp_op_generate_set_pref_keyserver)(cop, ckeyserver);
    ENCODE_FREE(keyserver);
    return ret;
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1execute(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_execute)(cop);
}

//F(op_: cd, handle: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1get_1key(JNIEnv *jenv, jobject jobj, jobject op, jobject handle) {
    void *cop = Handle2Ptr(jenv, op);
    rnp_key_handle_t chandle = NULL;
    rnp_result_t ret = dlF(rnp_op_generate_get_key)(cop, CPTR(handle));
    AddHandle(jenv, handle, chandle);
    return ret;
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1generate_1destroy(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_generate_destroy)(cop);
}

//F(key: cd, output: cd, flags: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1export(JNIEnv *jenv, jobject jobj, jobject key, jobject output, jint flags) {
    void *ckey = Handle2Ptr(jenv, key);
    void *coutput = Handle2Ptr(jenv, output);
    return dlF(rnp_key_export)(ckey, coutput, flags);
}

//F(key: cd, subkey: cd, uid: str, output: cd, flags: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1export_1autocrypt(JNIEnv *jenv, jobject jobj, jobject key, jobject subkey, jobject uid, jobject output, jint flags) {
    void *ckey = Handle2Ptr(jenv, key);
    void *csubkey = Handle2Ptr(jenv, subkey);
    void *coutput = Handle2Ptr(jenv, output);
    ENCODE_1STRING(uid);
    rnp_result_t ret = dlF(rnp_key_export_autocrypt)(ckey, csubkey, cuid, coutput, flags);
    ENCODE_FREE(uid);
    return ret;
}

//F(key: cd, output: cd, flags: int, hash: str, code: str, reason: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1export_1revocation(JNIEnv *jenv, jobject jobj, jobject key, jobject output, jint flags, jobject hash, jobject code, jobject reason) {
    void *ckey = Handle2Ptr(jenv, key);
    void *coutput = Handle2Ptr(jenv, output);
    ENCODE_3STRINGS(hash, code, reason);
    rnp_result_t ret = dlF(rnp_key_export_revocation)(ckey, coutput, flags, chash, ccode, creason);
    ENCODE_FREE3(hash, code, reason);
    return ret;
}

//F(key: cd, flags: int, hash: str, code: str, reason: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1revoke(JNIEnv *jenv, jobject jobj, jobject key, jint flags, jobject hash, jobject code, jobject reason) {
    void *ckey = Handle2Ptr(jenv, key);
    ENCODE_3STRINGS(hash, code, reason);
    rnp_result_t ret = dlF(rnp_key_revoke)(ckey, flags, chash, ccode, creason);
    ENCODE_FREE3(hash, code, reason);
    return ret;
}

//F(key: cd, flags: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1remove(JNIEnv *jenv, jobject jobj, jobject key, jint flags) {
    void *ckey = Handle2Ptr(jenv, key);
    return dlF(rnp_key_remove)(ckey, flags);
}

//F(input_: cd, contents: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1guess_1contents(JNIEnv *jenv, jobject jobj, jobject input, jobject contents) {
    void *cinput = Handle2Ptr(jenv, input);
    char *ccontents = NULL;
    rnp_result_t ret = dlF(rnp_guess_contents)(cinput, CPTR(contents));
    AddHandle(jenv, contents, ccontents);
    return ret;
}

//F(input_: cd, output: cd, type_: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1enarmor(JNIEnv *jenv, jobject jobj, jobject input, jobject output, jobject type) {
    void *cinput = Handle2Ptr(jenv, input);
    void *coutput = Handle2Ptr(jenv, output);
    ENCODE_1STRING(type);
    rnp_result_t ret = dlF(rnp_enarmor)(cinput, coutput, ctype);
    ENCODE_FREE(type);
    return ret;
}

//F(input_: cd, output: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1dearmor(JNIEnv *jenv, jobject jobj, jobject input, jobject output) {
    void *cinput = Handle2Ptr(jenv, input);
    void *coutput = Handle2Ptr(jenv, output);
    return dlF(rnp_dearmor)(cinput, coutput);
}

//F(key: cd, uid: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1primary_1uid(JNIEnv *jenv, jobject jobj, jobject key, jobject uid) {
    void *ckey = Handle2Ptr(jenv, key);
    char *cuid = NULL;
    rnp_result_t ret = dlF(rnp_key_get_primary_uid)(ckey, CPTR(uid));
    AddHandle(jenv, uid, cuid);
    return ret;
}

///F(key: cd, count: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1uid_1count(JNIEnv *jenv, jobject jobj, jobject key, jobject count) {
    void *ckey = Handle2Ptr(jenv, key);
    size_t ccount = 0;
    rnp_result_t ret = dlF(rnp_key_get_uid_count)(ckey, CPTR(count));
    AddInteger(jenv, count, (jint)ccount);
    return ret;
}

//F(key: cd, idx: int, uid: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1uid_1at(JNIEnv *jenv, jobject jobj, jobject key, jint idx, jobject uid) {
    void *ckey = Handle2Ptr(jenv, key);
    char *cuid = NULL;
    rnp_result_t ret = dlF(rnp_key_get_uid_at)(ckey, idx, CPTR(uid));
    AddStrHandle(jenv, uid, cuid);
    return ret;
}

//F(key: cd, idx: int, uid: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1uid_1handle_1at(JNIEnv *jenv, jobject jobj, jobject key, jint idx, jobject uid) {
    void *ckey = Handle2Ptr(jenv, key);
    rnp_uid_handle_t cuid = NULL;
    rnp_result_t ret = dlF(rnp_key_get_uid_handle_at)(ckey, idx, CPTR(uid));
    AddHandle(jenv, uid, cuid);
    return ret;
}

//F(uid: cd, type: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1uid_1get_1type(JNIEnv *jenv, jobject jobj, jobject uid, jobject type) {
    void *cuid = Handle2Ptr(jenv, uid);
    uint32_t ctype = 0;
    rnp_result_t ret = dlF(rnp_uid_get_type)(cuid, CPTR(type));
    AddInteger(jenv, type, (jint)ctype);
    return ret;
}

//F(uid: cd, data: [cd], size: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1uid_1get_1data(JNIEnv *jenv, jobject jobj, jobject uid, jobject data, jobject size) {
    void *cuid = Handle2Ptr(jenv, uid);
    void *cdata = NULL;
    size_t csize = 0;
    rnp_result_t ret = dlF(rnp_uid_get_data)(cuid, CPTR(data), CPTR(size));
    AddHandle(jenv, data, cdata);
    AddLong(jenv, size, csize);
    return ret;
}

//F(uid: cd, primary: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1uid_1is_1primary(JNIEnv *jenv, jobject jobj, jobject uid, jobject primary) {
    void *cuid = Handle2Ptr(jenv, uid);
    bool cprimary = false;
    rnp_result_t ret = dlF(rnp_uid_is_primary)(cuid, CPTR(primary));
    AddBoolean(jenv, primary, cprimary);
    return ret;
}

//F(uid: cd, valid: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1uid_1is_1valid(JNIEnv *jenv, jobject jobj, jobject uid, jobject valid) {
    void *cuid = Handle2Ptr(jenv, uid);
    bool cvalid = false;
    rnp_result_t ret = dlF(rnp_uid_is_valid)(cuid, CPTR(valid));
    AddBoolean(jenv, valid, cvalid);
    return ret;
}

//F(key: cd, count: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1signature_1count(JNIEnv *jenv, jobject jobj, jobject key, jobject count) {
    void *ckey = Handle2Ptr(jenv, key);
    size_t ccount = 0;
    rnp_result_t ret = dlF(rnp_key_get_signature_count)(ckey, CPTR(count));
    AddInteger(jenv, count, (jint)ccount);
    return ret;
}

//F(key: cd, idx: int, sig: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1signature_1at(JNIEnv *jenv, jobject jobj, jobject key, jint idx, jobject sig) {
    void *ckey = Handle2Ptr(jenv, key);
    rnp_signature_handle_t csig = NULL;
    rnp_result_t ret = dlF(rnp_key_get_signature_at)(ckey, idx, CPTR(sig));
    AddHandle(jenv, sig, csig);
    return ret;
}

//F(key: cd, sig: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1revocation_1signature(JNIEnv *jenv, jobject jobj, jobject key, jobject sig) {
    void *ckey = Handle2Ptr(jenv, key);
    rnp_signature_handle_t csig = NULL;
    rnp_result_t ret = dlF(rnp_key_get_revocation_signature)(ckey, CPTR(sig));
    AddHandle(jenv, sig, csig);
    return ret;
}

//F(uid: cd, count: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1uid_1get_1signature_1count(JNIEnv *jenv, jobject jobj, jobject uid, jobject count) {
    void *cuid = Handle2Ptr(jenv, uid);
    size_t ccount = 0;
    rnp_result_t ret = dlF(rnp_uid_get_signature_count)(cuid, CPTR(count));
    AddInteger(jenv, count, (jint)ccount);
    return ret;
}

//F(uid: cd, idx: int, sig: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1uid_1get_1signature_1at(JNIEnv *jenv, jobject jobj, jobject uid, jint idx, jobject sig) {
    void *cuid = Handle2Ptr(jenv, uid);
    rnp_signature_handle_t csig = NULL;
    rnp_result_t ret = dlF(rnp_uid_get_signature_at)(cuid, idx, CPTR(sig));
    AddHandle(jenv, sig, csig);
    return ret;
}

//F(uid: cd, sig: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1signature_1get_1type(JNIEnv *jenv, jobject jobj, jobject sig, jobject type) {
    void *csig = Handle2Ptr(jenv, sig);
    char *ctype = NULL;
    rnp_result_t ret = dlF(rnp_signature_get_type)(csig, CPTR(type));
    AddStrHandle(jenv, type, ctype);
    return ret;
}

//F(sig: cd, alg: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1signature_1get_1alg(JNIEnv *jenv, jobject jobj, jobject sig, jobject alg) {
    void *csig = Handle2Ptr(jenv, sig);
    char *calg = NULL;
    rnp_result_t ret = dlF(rnp_signature_get_alg)(csig, CPTR(alg));
    AddStrHandle(jenv, alg, calg);
    return ret;
}

//F(sig: cd, alg: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1signature_1get_1hash_1alg(JNIEnv *jenv, jobject jobj, jobject sig, jobject alg) {
    void *csig = Handle2Ptr(jenv, sig);
    char *calg = NULL;
    rnp_result_t ret = dlF(rnp_signature_get_hash_alg)(csig, CPTR(alg));
    AddStrHandle(jenv, alg, calg);
    return ret;
}

//F(sig: cd, create: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1signature_1get_1creation(JNIEnv *jenv, jobject jobj, jobject sig, jobject create) {
    void *csig = Handle2Ptr(jenv, sig);
    uint32_t ccreate = 0;
    rnp_result_t ret = dlF(rnp_signature_get_creation)(csig, CPTR(create));
    AddLong(jenv, create, ccreate);
    return ret;
}

//F(sig: cd, result: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1signature_1get_1keyid(JNIEnv *jenv, jobject jobj, jobject sig, jobject result) {
    void *csig = Handle2Ptr(jenv, sig);
    char *cresult = NULL;
    rnp_result_t ret = dlF(rnp_signature_get_keyid)(csig, CPTR(result));
    AddStrHandle(jenv, result, cresult);
    return ret;
}

//F(sig: cd, key: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1signature_1get_1signer(JNIEnv *jenv, jobject jobj, jobject sig, jobject key) {
    void *csig = Handle2Ptr(jenv, sig);
    rnp_key_handle_t ckey = NULL;
    rnp_result_t ret = dlF(rnp_signature_get_signer)(csig, CPTR(key));
    AddHandle(jenv, key, ckey);
    return ret;
}

//F(sig: cd, flags: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1signature_1is_1valid(JNIEnv *jenv, jobject jobj, jobject sig, int flags) {
    void *csig = Handle2Ptr(jenv, sig);
    return dlF(rnp_signature_is_valid)(csig, flags);
}

//F(sig: cd, flags: int, json: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1signature_1packet_1to_1json(JNIEnv *jenv, jobject jobj, jobject sig, jint flags, jobject json) {
    void *csig = Handle2Ptr(jenv, sig);
    char *cjson = NULL;
    rnp_result_t ret = dlF(rnp_signature_packet_to_json)(csig, flags, CPTR(json));
    AddStrHandle(jenv, json, cjson);
    return ret;
}

//F(sig: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1signature_1handle_1destroy(JNIEnv *jenv, jobject jobj, jobject sig) {
    void *csig = Handle2Ptr(jenv, sig);
    return dlF(rnp_signature_handle_destroy)(csig);
}

//F(uid: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1uid_1is_1revoked(JNIEnv *jenv, jobject jobj, jobject uid, jobject result) {
    void *cuid = Handle2Ptr(jenv, uid);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_uid_is_revoked)(cuid, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(uid: cd, sig: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1uid_1get_1revocation_1signature(JNIEnv *jenv, jobject jobj, jobject uid, jobject sig) {
    void *cuid = Handle2Ptr(jenv, uid);
    rnp_signature_handle_t csig = NULL;
    rnp_result_t ret = dlF(rnp_uid_get_revocation_signature)(cuid, CPTR(sig));
    AddHandle(jenv, sig, csig);
    return ret;
}

//F(uid: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1uid_1handle_1destroy(JNIEnv *jenv, jobject jobj, jobject uid) {
    void *cuid = Handle2Ptr(jenv, uid);
    return dlF(rnp_uid_handle_destroy)(cuid);
}

//F(key: cd, count: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1subkey_1count(JNIEnv *jenv, jobject jobj, jobject key, jobject count) {
    void *ckey = Handle2Ptr(jenv, key);
    size_t ccount = 0;
    rnp_result_t ret = dlF(rnp_key_get_subkey_count)(ckey, CPTR(count));
    AddInteger(jenv, count, (jint)ccount);
    return ret;
}

//F(key: cd, idx: int, subkey: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1subkey_1at(JNIEnv *jenv, jobject jobj, jobject key, jint idx, jobject subkey) {
    void *ckey = Handle2Ptr(jenv, key);
    rnp_key_handle_t csubkey = NULL;
    rnp_result_t ret = dlF(rnp_key_get_subkey_at)(ckey, idx, CPTR(subkey));
    AddHandle(jenv, subkey, csubkey);
    return ret;
}

//F(key: cd, alg: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1alg(JNIEnv *jenv, jobject jobj, jobject key, jobject alg) {
    void *ckey = Handle2Ptr(jenv, key);
    char *calg = NULL;
    rnp_result_t ret = dlF(rnp_key_get_alg)(ckey, CPTR(alg));
    AddStrHandle(jenv, alg, calg);
    return ret;
}

//F(key: cd, bits: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1bits(JNIEnv *jenv, jobject jobj, jobject key, jobject bits) {
    void *ckey = Handle2Ptr(jenv, key);
    uint32_t cbits = 0;
    rnp_result_t ret = dlF(rnp_key_get_bits)(ckey, CPTR(bits));
    AddInteger(jenv, bits, cbits);
    return ret;
}

//F(key: cd, qbits: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1dsa_1qbits(JNIEnv *jenv, jobject jobj, jobject key, jobject qbits) {
    void *ckey = Handle2Ptr(jenv, key);
    uint32_t cqbits = 0;
    rnp_result_t ret = dlF(rnp_key_get_dsa_qbits)(ckey, CPTR(qbits));
    AddInteger(jenv, qbits, cqbits);
    return ret;
}

//F(key: cd, curve: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1curve(JNIEnv *jenv, jobject jobj, jobject key, jobject curve) {
    void *ckey = Handle2Ptr(jenv, key);
    char *ccurve = NULL;
    rnp_result_t ret = dlF(rnp_key_get_curve)(ckey, CPTR(curve));
    AddStrHandle(jenv, curve, ccurve);
    return ret;
}

//F(key: cd, uid: str, hash_: str, expiration: int, key_flags: int, primary: bool) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1add_1uid(JNIEnv *jenv, jobject jobj, jobject key, jobject uid, jobject hash, jlong expiration, jint key_flags, jboolean primary) {
    void *ckey = Handle2Ptr(jenv, key);
    ENCODE_2STRINGS(uid, hash);
    rnp_result_t ret = dlF(rnp_key_add_uid)(ckey, cuid, chash, (uint32_t)expiration, (uint8_t)key_flags, primary);
    ENCODE_FREE2(uid, hash);
    return ret;
}

//F(key: cd, fprint: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1fprint(JNIEnv *jenv, jobject jobj, jobject key, jobject fprint) {
    void *ckey = Handle2Ptr(jenv, key);
    char *cfprint = NULL;
    rnp_result_t ret = dlF(rnp_key_get_fprint)(ckey, CPTR(fprint));
    AddStrHandle(jenv, fprint, cfprint);
    return ret;
}

//F(key: cd, keyid: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1keyid(JNIEnv *jenv, jobject jobj, jobject key, jobject keyid) {
    void *ckey = Handle2Ptr(jenv, key);
    char *ckeyid = NULL;
    rnp_result_t ret = dlF(rnp_key_get_keyid)(ckey, CPTR(keyid));
    AddStrHandle(jenv, keyid, ckeyid);
    return ret;
}

//F(key: cd, grip: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1grip(JNIEnv *jenv, jobject jobj, jobject key, jobject grip) {
    void *ckey = Handle2Ptr(jenv, key);
    char *cgrip = NULL;
    rnp_result_t ret = dlF(rnp_key_get_grip)(ckey, CPTR(grip));
    AddStrHandle(jenv, grip, cgrip);
    return ret;
}

//F(key: cd, grip: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1primary_1grip(JNIEnv *jenv, jobject jobj, jobject key, jobject grip) {
    void *ckey = Handle2Ptr(jenv, key);
    char *cgrip = NULL;
    rnp_result_t ret = dlF(rnp_key_get_primary_grip)(ckey, CPTR(grip));
    AddStrHandle(jenv, grip, cgrip);
    return ret;
}

//F(key: cd, fprint: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1primary_1fprint(JNIEnv *jenv, jobject jobj, jobject key, jobject fprint) {
    void *ckey = Handle2Ptr(jenv, key);
    char *cfprint = NULL;
    rnp_result_t ret = dlF(rnp_key_get_primary_fprint)(ckey, CPTR(fprint));
    AddStrHandle(jenv, fprint, cfprint);
    return ret;
}

//F(key: cd, usage: str, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1allows_1usage(JNIEnv *jenv, jobject jobj, jobject key, jobject usage, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    ENCODE_1STRING(usage);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_allows_usage)(ckey, cusage, CPTR(result));
    ENCODE_FREE(usage);
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1creation(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    uint32_t cresult = 0;
    rnp_result_t ret = dlF(rnp_key_get_creation)(ckey, CPTR(result));
    AddLong(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1expiration(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    uint32_t cresult = 0;
    rnp_result_t ret = dlF(rnp_key_get_expiration)(ckey, CPTR(result));
    AddLong(jenv, result, cresult);
    return ret;
}

//F(key: cd, expiry: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1set_1expiration(JNIEnv *jenv, jobject jobj, jobject key, jlong expiry) {
    void *ckey = Handle2Ptr(jenv, key);
    return dlF(rnp_key_set_expiration)(ckey, (uint32_t)expiry);
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1is_1valid(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_is_valid)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1valid_1till(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    uint32_t cresult = 0;
    rnp_result_t ret = dlF(rnp_key_valid_till)(ckey, CPTR(result));
    AddLong(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1is_1revoked(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_is_revoked)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1revocation_1reason(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    char *cresult = NULL;
    rnp_result_t ret = dlF(rnp_key_get_revocation_reason)(ckey, CPTR(result));
    AddStrHandle(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1is_1superseded(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_is_superseded)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1is_1compromised(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_is_compromised)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1is_1retired(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_is_retired)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1is_1locked(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_is_locked)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, type: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1protection_1type(JNIEnv *jenv, jobject jobj, jobject key, jobject type) {
    void *ckey = Handle2Ptr(jenv, key);
    char *ctype = NULL;
    rnp_result_t ret = dlF(rnp_key_get_protection_type)(ckey, CPTR(type));
    AddStrHandle(jenv, type, ctype);
    return ret;
}

//F(key: cd, type: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1protection_1mode(JNIEnv *jenv, jobject jobj, jobject key, jobject mode) {
    void *ckey = Handle2Ptr(jenv, key);
    char *cmode = NULL;
    rnp_result_t ret = dlF(rnp_key_get_protection_mode)(ckey, CPTR(mode));
    AddStrHandle(jenv, mode, cmode);
    return ret;
}

//F(key: cd, type: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1protection_1cipher(JNIEnv *jenv, jobject jobj, jobject key, jobject cipher) {
    void *ckey = Handle2Ptr(jenv, key);
    char *ccipher = NULL;
    rnp_result_t ret = dlF(rnp_key_get_protection_cipher)(ckey, CPTR(cipher));
    AddStrHandle(jenv, cipher, ccipher);
    return ret;
}

//F(key: cd, type: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1protection_1hash(JNIEnv *jenv, jobject jobj, jobject key, jobject hash) {
    void *ckey = Handle2Ptr(jenv, key);
    char *chash = NULL;
    rnp_result_t ret = dlF(rnp_key_get_protection_hash)(ckey, CPTR(hash));
    AddStrHandle(jenv, hash, chash);
    return ret;
}

//F(key: cd, type: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1get_1protection_1iterations(JNIEnv *jenv, jobject jobj, jobject key, jobject iterations) {
    void *ckey = Handle2Ptr(jenv, key);
    size_t citerations = 0;
    rnp_result_t ret = dlF(rnp_key_get_protection_iterations)(ckey, CPTR(iterations));
    AddInteger(jenv, iterations, (jint)citerations);
    return ret;
}

//F(key: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1lock(JNIEnv *jenv, jobject jobj, jobject key) {
    void *ckey = Handle2Ptr(jenv, key);
    return dlF(rnp_key_lock)(ckey);
}

//F(key: cd, password: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1unlock(JNIEnv *jenv, jobject jobj, jobject key, jobject password) {
    void *ckey = Handle2Ptr(jenv, key);
    ENCODE_1STRING(password);
    rnp_result_t ret = dlF(rnp_key_unlock)(ckey, cpassword);
    ENCODE_FREE(password);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1is_1protected(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_is_protected)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(handle: cd, password: str, cipher: str, cipher_mode: str, hash_: str, iterations: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1protect(JNIEnv *jenv, jobject jobj, jobject handle, jobject password, jobject cipher, jobject cipher_mode, jobject hash, jint iterations) {
    void *chandle = Handle2Ptr(jenv, handle);
    ENCODE_PROLOG(4);
    ENCODE_STRING(password);
    ENCODE_NEXT3STRINGS(cipher, cipher_mode, hash);
    rnp_result_t ret = dlF(rnp_key_protect)(chandle, cpassword, ccipher, ccipher_mode, chash, iterations);
    ENCODE_FREE3(cipher, cipher_mode, hash);
    ENCODE_FREE(password);
    return ret;
}

//F(key: cd, password: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1unprotect(JNIEnv *jenv, jobject jobj, jobject key, jobject password) {
    void *ckey = Handle2Ptr(jenv, key);
    ENCODE_1STRING(password);
    rnp_result_t ret = dlF(rnp_key_unprotect)(ckey, cpassword);
    ENCODE_FREE(password);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1is_1primary(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_is_primary)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1is_1sub(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_is_sub)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1have_1secret(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_have_secret)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, result: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1have_1public(JNIEnv *jenv, jobject jobj, jobject key, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    bool cresult = false;
    rnp_result_t ret = dlF(rnp_key_have_public)(ckey, CPTR(result));
    AddBoolean(jenv, result, cresult);
    return ret;
}

//F(key: cd, secret: bool, flags: int, result: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1packets_1to_1json(JNIEnv *jenv, jobject jobj, jobject key, jboolean secret, jint flags, jobject result) {
    void *ckey = Handle2Ptr(jenv, key);
    char *cresult = NULL;
    rnp_result_t ret = dlF(rnp_key_packets_to_json)(ckey, secret, flags, CPTR(result));
    AddStrHandle(jenv, result, cresult);
    return ret;
}

//F(input_: cd, flags: int, result: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1dump_1packets_1to_1json(JNIEnv *jenv, jobject jobj, jobject input, jint flags, jobject result) {
    void *cinput = Handle2Ptr(jenv, input);
    char *cresult = NULL;
    rnp_result_t ret = dlF(rnp_dump_packets_to_json)(cinput, flags, CPTR(result));
    AddStrHandle(jenv, result, cresult);
    return ret;
}

//F(input_: cd, output: cd, flags: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1dump_1packets_1to_1output(JNIEnv *jenv, jobject jobj, jobject input, jobject output, jint flags) {
    void *cinput = Handle2Ptr(jenv, input);
    void *coutput = Handle2Ptr(jenv, output);
    return dlF(rnp_dump_packets_to_output)(cinput, coutput, flags);
}

//F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1create(JNIEnv *jenv, jobject jobj, jobject op, jobject ffi, jobject input, jobject output) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cinput = Handle2Ptr(jenv, input);
    void *coutput = Handle2Ptr(jenv, output);
    rnp_op_sign_t cop = NULL;
    rnp_result_t ret = dlF(rnp_op_sign_create)(CPTR(op), cffi, cinput, coutput);
    AddHandle(jenv, op, cop);
    return ret;
}

//F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1cleartext_1create(JNIEnv *jenv, jobject jobj, jobject op, jobject ffi, jobject input, jobject output) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cinput = Handle2Ptr(jenv, input);
    void *coutput = Handle2Ptr(jenv, output);
    rnp_op_sign_t cop = NULL;
    rnp_result_t ret = dlF(rnp_op_sign_cleartext_create)(CPTR(op), cffi, cinput, coutput);
    AddHandle(jenv, op, cop);
    return ret;
}

//F(op_: [cd], ffi: cd, input_: cd, signature: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1detached_1create(JNIEnv *jenv, jobject jobj, jobject op, jobject ffi, jobject input, jobject signature) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cinput = Handle2Ptr(jenv, input);
    void *csignature = Handle2Ptr(jenv, signature);
    rnp_op_sign_t cop = NULL;
    rnp_result_t ret = dlF(rnp_op_sign_detached_create)(CPTR(op), cffi, cinput, csignature);
    AddHandle(jenv, op, cop);
    return ret;
}

//F(op_: cd, key: cd, sig: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1add_1signature(JNIEnv *jenv, jobject jobj, jobject op, jobject key, jobject sig) {
    void *cop = Handle2Ptr(jenv, op);
    void *ckey = Handle2Ptr(jenv, key);
    rnp_op_sign_signature_t csig = NULL;
    rnp_result_t ret = dlF(rnp_op_sign_add_signature)(cop, ckey, CPTR(sig));
    AddHandle(jenv, sig, csig);
    return ret;
}

//F(sig: cd, hash_: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1signature_1set_1hash(JNIEnv *jenv, jobject jobj, jobject sig, jobject hash) {
    void *csig = Handle2Ptr(jenv, sig);
    ENCODE_1STRING(hash);
    rnp_result_t ret = dlF(rnp_op_sign_signature_set_hash)(csig, chash);
    ENCODE_FREE(hash);
    return ret;
}

//F(sig: cd, create: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1signature_1set_1creation_1time(JNIEnv *jenv, jobject jobj, jobject sig, jlong create) {
    void *csig = Handle2Ptr(jenv, sig);
    return dlF(rnp_op_sign_signature_set_creation_time)(csig, (uint32_t)create);
}

//F(sig: cd, expires: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1signature_1set_1expiration_1time(JNIEnv *jenv, jobject jobj, jobject sig, jlong expires) {
    void *csig = Handle2Ptr(jenv, sig);
    return dlF(rnp_op_sign_signature_set_expiration_time)(csig, (uint32_t)expires);
}

//F(op_: cd, compression: str, level: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1set_1compression(JNIEnv *jenv, jobject jobj, jobject op, jobject compression, jint level) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(compression);
    rnp_result_t ret = dlF(rnp_op_sign_set_compression)(cop, ccompression, level);
    ENCODE_FREE(compression);
    return ret;
}

//F(op_: cd, armored: bool) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1set_1armor(JNIEnv *jenv, jobject jobj, jobject op, jboolean armored) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_sign_set_armor)(cop, armored);
}

//F(op_: cd, hash_: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1set_1hash(JNIEnv *jenv, jobject jobj, jobject op, jobject hash) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(hash);
    rnp_result_t ret = dlF(rnp_op_sign_set_hash)(cop, chash);
    ENCODE_FREE(hash);
    return ret;
}

//F(op_: cd, create: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1set_1creation_1time(JNIEnv *jenv, jobject jobj, jobject op, jlong create) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_sign_set_creation_time)(cop, (uint32_t)create);
}

//F(op_: cd, expire: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1set_1expiration_1time(JNIEnv *jenv, jobject jobj, jobject op, jlong expire) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_sign_set_expiration_time)(cop, (uint32_t)expire);
}

//F(op_: cd, filename: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1set_1file_1name(JNIEnv *jenv, jobject jobj, jobject op, jobject filename) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(filename);
    rnp_result_t ret = dlF(rnp_op_sign_set_file_name)(cop, cfilename);
    ENCODE_FREE(filename);
    return ret;
}

//F(op_: cd, mtime: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1set_1file_1mtime(JNIEnv *jenv, jobject jobj, jobject op, jlong mtime) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_sign_set_file_mtime)(cop, (uint32_t)mtime);
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1execute(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_sign_execute)(cop);
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1sign_1destroy(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_sign_destroy)(cop);
}

//F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1create(JNIEnv *jenv, jobject jobj, jobject op, jobject ffi, jobject input, jobject output) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cinput = Handle2Ptr(jenv, input);
    void *coutput = Handle2Ptr(jenv, output);
    rnp_op_verify_t cop = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_create)(CPTR(op), cffi, cinput, coutput);
    AddHandle(jenv, op, cop);
    return ret;
}

//F(op_: [cd], ffi: cd, input_: cd, signature: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1detached_1create(JNIEnv *jenv, jobject jobj, jobject op, jobject ffi, jobject input, jobject signature) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cinput = Handle2Ptr(jenv, input);
    void *csignature = Handle2Ptr(jenv, signature);
    rnp_op_verify_t cop = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_detached_create)(CPTR(op), cffi, cinput, csignature);
    AddHandle(jenv, op, cop);
    return ret;
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1execute(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_verify_execute)(cop);
}

//F(op_: cd, count: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1signature_1count(JNIEnv *jenv, jobject jobj, jobject op, jobject count) {
    void *cop = Handle2Ptr(jenv, op);
    size_t ccount = 0;
    rnp_result_t ret = dlF(rnp_op_verify_get_signature_count)(cop, CPTR(count));
    AddInteger(jenv, count, (jint)ccount);
    return ret;
}

//F(op_: cd, idx: int, sig: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1signature_1at(JNIEnv *jenv, jobject jobj, jobject op, jint idx, jobject sig) {
    void *cop = Handle2Ptr(jenv, op);
    rnp_op_verify_signature_t csig = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_get_signature_at)(cop, idx, CPTR(sig));
    AddHandle(jenv, sig, csig);
    return ret;
}

//F(op_: cd, filename: [cd], mtime: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1file_1info(JNIEnv *jenv, jobject jobj, jobject op, jobject filename, jobject mtime) {
    void *cop = Handle2Ptr(jenv, op);
    char *cfilename = NULL;
    uint32_t cmtime = 0;
    rnp_result_t ret = dlF(rnp_op_verify_get_file_info)(cop, CPTR(filename), CPTR(mtime));
    AddStrHandle(jenv, filename, cfilename);
    AddLong(jenv, mtime, cmtime);
    return ret;
}

//F(op: cd, mode: [str], cipher: [str], valid: [bool]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1protection_1info(JNIEnv *jenv, jobject jobj, jobject op, jobject mode, jobject cipher, jobject valid) {
    void *cop = Handle2Ptr(jenv, op);
    char *cmode = NULL;
    char *ccipher = NULL;
    bool cvalid = false;
    rnp_result_t ret = dlF(rnp_op_verify_get_protection_info)(cop, CPTR(mode), CPTR(cipher), CPTR(valid));
    AddStrHandle(jenv, mode, cmode);
    AddStrHandle(jenv, cipher, ccipher);
    AddBoolean(jenv, valid, cvalid);
    return ret;
}

//F(op: cd, count: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1recipient_1count(JNIEnv *jenv, jobject jobj, jobject op, jobject count) {
    void *cop = Handle2Ptr(jenv, op);
    size_t ccount = 0;
    rnp_result_t ret = dlF(rnp_op_verify_get_recipient_count)(cop, CPTR(count));
    AddInteger(jenv, count, ccount);
    return ret;
}

//F(op: cd, recipient: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1used_1recipient(JNIEnv *jenv, jobject jobj, jobject op, jobject recipient) {
    void *cop = Handle2Ptr(jenv, op);
    rnp_recipient_handle_t crecipient = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_get_used_recipient)(cop, CPTR(recipient));
    AddHandle(jenv, recipient, crecipient);
    return ret;
}

//F(op: cd, idx: int, recipient: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1recipient_1at(JNIEnv *jenv, jobject jobj, jobject op, jint idx, jobject recipient) {
    void *cop = Handle2Ptr(jenv, op);
    rnp_recipient_handle_t crecipient = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_get_recipient_at)(cop, (size_t)idx, CPTR(recipient));
    AddHandle(jenv, recipient, crecipient);
    return ret;
}

//F(op: cd, count: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1symenc_1count(JNIEnv *jenv, jobject jobj, jobject op, jobject count) {
    void *cop = Handle2Ptr(jenv, op);
    size_t ccount = 0;
    rnp_result_t ret = dlF(rnp_op_verify_get_symenc_count)(cop, CPTR(count));
    AddInteger(jenv, count, ccount);
    return ret;
}

//F(op: cd, symenc: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1used_1symenc(JNIEnv *jenv, jobject jobj, jobject op, jobject symenc) {
    void *cop = Handle2Ptr(jenv, op);
    rnp_symenc_handle_t csymenc = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_get_used_symenc)(cop, CPTR(symenc));
    AddHandle(jenv, symenc, csymenc);
    return ret;
}

//F(op: cd, idx: int, symenc: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1get_1symenc_1at(JNIEnv *jenv, jobject jobj, jobject op, jint idx, jobject symenc) {
    void *cop = Handle2Ptr(jenv, op);
    rnp_symenc_handle_t csymenc = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_get_symenc_at)(cop, (size_t)idx, CPTR(symenc));
    AddHandle(jenv, symenc, csymenc);
    return ret;
}

//F(recipient: cd, keyid: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1recipient_1get_1keyid(JNIEnv *jenv, jobject jobj, jobject recipient, jobject keyid) {
    void *crecipient = Handle2Ptr(jenv, recipient);
    char *ckeyid = NULL;
    rnp_result_t ret = dlF(rnp_recipient_get_keyid)(crecipient, CPTR(keyid));
    AddStrHandle(jenv, keyid, ckeyid);
    return ret;
}

//F(recipient: cd, alg: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1recipient_1get_1alg(JNIEnv *jenv, jobject jobj, jobject recipient, jobject alg) {
    void *crecipient = Handle2Ptr(jenv, recipient);
    char *calg = NULL;
    rnp_result_t ret = dlF(rnp_recipient_get_alg)(crecipient, CPTR(alg));
    AddStrHandle(jenv, alg, calg);
    return ret;
}

//F(symenc: cd, cipher: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1symenc_1get_1cipher(JNIEnv *jenv, jobject jobj, jobject symenc, jobject cipher) {
    void *csymenc = Handle2Ptr(jenv, symenc);
    char *ccipher = NULL;
    rnp_result_t ret = dlF(rnp_symenc_get_cipher)(csymenc, CPTR(cipher));
    AddStrHandle(jenv, cipher, ccipher);
    return ret;
}

//F(symenc: cd, alg: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1symenc_1get_1aead_1alg(JNIEnv *jenv, jobject jobj, jobject symenc, jobject alg) {
    void *csymenc = Handle2Ptr(jenv, symenc);
    char *calg = NULL;
    rnp_result_t ret = dlF(rnp_symenc_get_aead_alg)(csymenc, CPTR(alg));
    AddStrHandle(jenv, alg, calg);
    return ret;
}

//F(symenc: cd, alg: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1symenc_1get_1hash_1alg(JNIEnv *jenv, jobject jobj, jobject symenc, jobject alg) {
    void *csymenc = Handle2Ptr(jenv, symenc);
    char *calg = NULL;
    rnp_result_t ret = dlF(rnp_symenc_get_hash_alg)(csymenc, CPTR(alg));
    AddStrHandle(jenv, alg, calg);
    return ret;
}

//F(symenc: cd, type: [str]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1symenc_1get_1s2k_1type(JNIEnv *jenv, jobject jobj, jobject symenc, jobject type) {
    void *csymenc = Handle2Ptr(jenv, symenc);
    char *ctype = NULL;
    rnp_result_t ret = dlF(rnp_symenc_get_s2k_type)(csymenc, CPTR(type));
    AddStrHandle(jenv, type, ctype);
    return ret;
}

//F(symenc: cd, iterations: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1symenc_1get_1s2k_1iterations(JNIEnv *jenv, jobject jobj, jobject symenc, jobject iterations) {
    void *csymenc = Handle2Ptr(jenv, symenc);
    uint32_t citerations = 0;
    rnp_result_t ret = dlF(rnp_symenc_get_s2k_iterations)(csymenc, CPTR(iterations));
    AddInteger(jenv, iterations, citerations);
    return ret;
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1destroy(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_verify_destroy)(cop);
}

//F(sig: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1signature_1get_1status(JNIEnv *jenv, jobject jobj, jobject sig) {
    void *csig = Handle2Ptr(jenv, sig);
    return dlF(rnp_op_verify_signature_get_status)(csig);
}

//F(sig: cd, handle: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1signature_1get_1handle(JNIEnv *jenv, jobject jobj, jobject sig,jobject handle) {
    void *csig = Handle2Ptr(jenv, sig);
    rnp_signature_handle_t chandle = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_signature_get_handle)(csig, CPTR(handle));
    AddHandle(jenv, handle, chandle);
    return ret;
}

//F(sig: cd, hash_: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1signature_1get_1hash(JNIEnv *jenv, jobject jobj, jobject sig, jobject hash) {
    void *csig = Handle2Ptr(jenv, sig);
    char *chash = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_signature_get_hash)(csig, CPTR(hash));
    AddStrHandle(jenv, hash, chash);
    return ret;
}

//F(sig: cd, key: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1signature_1get_1key(JNIEnv *jenv, jobject jobj, jobject sig, jobject key) {
    void *csig = Handle2Ptr(jenv, sig);
    rnp_key_handle_t ckey = NULL;
    rnp_result_t ret = dlF(rnp_op_verify_signature_get_key)(csig, CPTR(key));
    AddHandle(jenv, key, ckey);
    return ret;
}

//F(sig: cd, create: [int], expires: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1verify_1signature_1get_1times(JNIEnv *jenv, jobject jobj, jobject sig, jobject create, jobject expires) {
    void *csig = Handle2Ptr(jenv, sig);
    uint32_t ccreate = 0, cexpires = 0;
    rnp_result_t ret = dlF(rnp_op_verify_signature_get_times)(csig, CPTR(create), CPTR(expires));
    AddLong(jenv, create, ccreate);
    AddLong(jenv, expires, cexpires);
    return ret;
}

//F(ptr: cd)
JNIEXPORT void JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1buffer_1destroy(JNIEnv *jenv, jobject jobj, jobject ptr) {
    void *cptr = Handle2Ptr(jenv, ptr);
    dlF(rnp_buffer_destroy)(cptr);
}

//F(ptr: cd, size: int)
JNIEXPORT void JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1buffer_1clear(JNIEnv *jenv, jobject jobj, jobject ptr, jlong size) {
    void *cptr = Handle2Ptr(jenv, ptr);
    dlF(rnp_buffer_clear)(cptr, (size_t)size);
}

//F(input_: [cd], path: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1input_1from_1path(JNIEnv *jenv, jobject jobj, jobject input, jobject path) {
    ENCODE_1STRING(path);
    rnp_input_t cinput = NULL;
    rnp_result_t ret = dlF(rnp_input_from_path)(CPTR(input), cpath);
    ENCODE_FREE(path);
    AddHandle(jenv, input, cinput);
    return ret;
}

//F(input_: [cd], buf: bstr, buf_len: int, do_copy: bool) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1input_1from_1memory(JNIEnv *jenv, jobject jobj, jobject input, jobject buf, jlong buf_len, jboolean do_copy) {
    rnp_input_t cinput = NULL;
    ENCODE_1STRING(buf);
    rnp_result_t ret = dlF(rnp_input_from_memory)(CPTR(input), cbuf, (size_t)buf_len, do_copy);
    jobject hndInp = AddHandle(jenv, input, cinput);
    if(hndInp != NULL && cinput != NULL) {
        const char* fldId[] = { "retainsI", "Ljava/util/TreeMap;", NULL };
        jfieldID fidRetI = FindJField(jenv, jobj, fldId, NULL);
        jobject retainsI = (fidRetI!=NULL? (*jenv)->GetObjectField(jenv, jobj, fidRetI) : NULL);
        if((*jenv)->ExceptionCheck(jenv) == JNI_FALSE) {
            jobject hndRet = AddStrHandle(jenv, NULL, cbuf);
            jclass clsRet = NULL;
            const char* fldId[] = { "source", "Ljava/lang/Object;", NULL };
            jfieldID fidSrc = FindJField(jenv, hndRet, fldId, &clsRet);
            if(fidSrc != NULL)
                (*jenv)->SetObjectField(jenv, hndRet, fidSrc, buf);
            jfieldID fidSI = (*jenv)->GetFieldID(jenv, clsRet, "src_i", "I");
            if(fidSI != NULL)
                (*jenv)->SetIntField(jenv, hndRet, fidSI, _sctx[0]);
            if((*jenv)->ExceptionCheck(jenv) == JNI_FALSE)
                SetHandle(jenv, retainsI, hndInp, hndRet);
        }
    } else
        ENCODE_FREE(buf);
    return ret;
}

//F(input_: [cd], reader: Rop_input_reader_t, closer: Rop_input_closer_t, app_ctx: obj) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_nrnp_1input_1from_1callback(JNIEnv *jenv, jobject jobj, jobject input, jobject cb_ctx) {
    rnp_input_t cinput = NULL;
    void *ccb_ctx = Handle2Ptr(jenv, cb_ctx);
    rnp_result_t ret = dlF(rnp_input_from_callback)(&cinput, input_read_callback, input_close_callback, (void*)ccb_ctx);
    AddHandle(jenv, input, cinput);
    return ret;
}

//F(input_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_nrnp_1input_1destroy(JNIEnv *jenv, jobject jobj, jobject input) {
    void *cinput = Handle2Ptr(jenv, input);
    rnp_result_t ret = dlF(rnp_input_destroy)(cinput);
    const char* fldId[] = { "retainsI", "Ljava/util/TreeMap;", NULL };
    jfieldID fidRetI = FindJField(jenv, jobj, fldId, NULL);
    jobject retainsI = (fidRetI!=NULL? (*jenv)->GetObjectField(jenv, jobj, fidRetI) : NULL);
    if((*jenv)->ExceptionCheck(jenv) == JNI_FALSE)
        SetHandle(jenv, retainsI, input, NULL);
    return ret;
}

//F(output: [cd], path: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1to_1path(JNIEnv *jenv, jobject jobj, jobject output, jobject path) {
    rnp_output_t coutput = NULL;
    ENCODE_1STRING(path);
    rnp_result_t ret = dlF(rnp_output_to_path)(CPTR(output), cpath);
    ENCODE_FREE(path);
    AddHandle(jenv, output, coutput);
    return ret;
}

//F(output: [cd], path: str, flags: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1to_1file(JNIEnv *jenv, jobject jobj, jobject output, jobject path, jint flags) {
    rnp_output_t coutput = NULL;
    ENCODE_1STRING(path);
    rnp_result_t ret = dlF(rnp_output_to_file)(CPTR(output), cpath, flags);
    ENCODE_FREE(path);
    AddHandle(jenv, output, coutput);
    return ret;
}

//F(output: [cd], max_alloc: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1to_1memory(JNIEnv *jenv, jobject jobj, jobject output, jlong max_alloc) {
    rnp_output_t coutput = NULL;
    rnp_result_t ret = dlF(rnp_output_to_memory)(CPTR(output), (size_t)max_alloc);
    AddHandle(jenv, output, coutput);
    return ret;
}

//F(base: cd, output: [cd], type_: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1to_1armor(JNIEnv *jenv, jobject jobj, jobject base, jobject output, jobject type) {
    void *cbase = Handle2Ptr(jenv, base);
    rnp_output_t coutput = NULL;
    ENCODE_1STRING(type);
    rnp_result_t ret = dlF(rnp_output_to_armor)(cbase, CPTR(output), ctype);
    ENCODE_FREE(type);
    AddHandle(jenv, output, coutput);
    return ret;
}

//F(output: cd, buf: [cd], len_: [int], do_copy: bool) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1memory_1get_1buf(JNIEnv *jenv, jobject jobj, jobject output, jobject buf, jobject len, jboolean do_copy) {
    void *coutput = Handle2Ptr(jenv, output);
    uint8_t *cbuf = NULL;
    size_t clen = 0;
    rnp_result_t ret = dlF(rnp_output_memory_get_buf)(coutput, CPTR(buf), CPTR(len), do_copy);
    AddHandle(jenv, buf, cbuf);
    AddLong(jenv, len, clen);
    return ret;
}

//F(output: [cd], writer: Rop_output_writer_t, closer: Rop_output_closer_t, app_ctx: obj) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_nrnp_1output_1to_1callback(JNIEnv *jenv, jobject jobj, jobject output, jobject cb_ctx) {
    rnp_output_t coutput = NULL;
    void *ccb_ctx = Handle2Ptr(jenv, cb_ctx);
    rnp_result_t ret = dlF(rnp_output_to_callback)(&coutput, output_write_callback, output_close_callback, ccb_ctx);
    AddHandle(jenv, output, coutput);
    return ret;
}

//F(output: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1to_1null(JNIEnv *jenv, jobject jobj, jobject output) {
    rnp_output_t coutput = NULL;
    rnp_result_t ret = dlF(rnp_output_to_null)(CPTR(output));
    AddHandle(jenv, output, coutput);
    return ret;
}

//F(output: cd, data: obj, size: int, written: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1write(JNIEnv *jenv, jobject jobj, jobject output, jobject data, jlong size, jobject written) {
    void *coutput = Handle2Ptr(jenv, output);
    size_t cwritten = 0;
    ENCODE_1STRING(data);
    rnp_result_t ret = dlF(rnp_output_write)(coutput, cdata, (size_t)size, CPTR(written));
    ENCODE_FREE(data);
    AddLong(jenv, written, cwritten);
    return ret;
}

//F(output: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1finish(JNIEnv *jenv, jobject jobj, jobject output) {
    void *coutput = Handle2Ptr(jenv, output);
    return dlF(rnp_output_finish)(coutput);
}

//F(output: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_nrnp_1output_1destroy(JNIEnv *jenv, jobject jobj, jobject output) {
    void *coutput = Handle2Ptr(jenv, output);
    return dlF(rnp_output_destroy)(coutput);
}

//F(op_: [cd], ffi: cd, input_: cd, output: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1create(JNIEnv *jenv, jobject jobj, jobject op, jobject ffi, jobject input, jobject output) {
    rnp_op_encrypt_t cop = NULL;
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cinput = Handle2Ptr(jenv, input);
    void *coutput = Handle2Ptr(jenv, output);
    rnp_result_t ret = dlF(rnp_op_encrypt_create)(CPTR(op), cffi, cinput, coutput);
    AddHandle(jenv, op, cop);
    return ret;
}

//F(op_: cd, key: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1add_1recipient(JNIEnv *jenv, jobject jobj, jobject op, jobject key) {
    void *cop = Handle2Ptr(jenv, op);
    void *ckey = Handle2Ptr(jenv, key);
    return dlF(rnp_op_encrypt_add_recipient)(cop, ckey);
}

//F(op_: cd, key: cd, sig: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1add_1signature(JNIEnv *jenv, jobject jobj, jobject op, jobject key, jobject sig) {
    void *cop = Handle2Ptr(jenv, op);
    void *ckey = Handle2Ptr(jenv, key);
    rnp_op_sign_signature_t csig = NULL;
    rnp_result_t ret = dlF(rnp_op_encrypt_add_signature)(cop, ckey, CPTR(sig));
    AddHandle(jenv, sig, csig);
    return ret;
}

//F(op_: cd, hash_: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1hash(JNIEnv *jenv, jobject jobj, jobject op, jobject hash) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(hash);
    rnp_result_t ret = dlF(rnp_op_encrypt_set_hash)(cop, chash);
    ENCODE_FREE(hash);
    return ret;
}

//F(op_: cd, create: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1creation_1time(JNIEnv *jenv, jobject jobj, jobject op, jlong create) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_encrypt_set_creation_time)(cop, (uint32_t)create);
}

//F(op_: cd, expire: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1expiration_1time(JNIEnv *jenv, jobject jobj, jobject op, jlong expire) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_encrypt_set_expiration_time)(cop, (uint32_t)expire);
}

//F(op_: cd, password: str, s2k_hash: str, iterations: int,
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1add_1password(JNIEnv *jenv, jobject jobj, jobject op, jobject password, jobject s2k_hash, jint iterations, jobject s2k_cipher) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_3STRINGS(password, s2k_hash, s2k_cipher);
    rnp_result_t ret = dlF(rnp_op_encrypt_add_password)(cop, cpassword, cs2k_hash, iterations, cs2k_cipher);
    ENCODE_FREE3(password, s2k_hash, s2k_cipher);
    return ret;
}

//F(op_: cd, armored: bool) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1armor(JNIEnv *jenv, jobject jobj, jobject op, jboolean armored) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_encrypt_set_armor)(cop, armored);
}

//F(op_: cd, cipher: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1cipher(JNIEnv *jenv, jobject jobj, jobject op, jobject cipher) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(cipher);
    rnp_result_t ret = dlF(rnp_op_encrypt_set_cipher)(cop, ccipher);
    ENCODE_FREE(cipher);
    return ret;
}

//F(op_: cd, alg: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1aead(JNIEnv *jenv, jobject jobj, jobject op, jobject alg) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(alg);
    rnp_result_t ret = dlF(rnp_op_encrypt_set_aead)(cop, calg);
    ENCODE_FREE(alg);
    return ret;
}

//F(op_: cd, bits: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1aead_1bits(JNIEnv *jenv, jobject jobj, jobject op, jint bits) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_encrypt_set_aead_bits)(cop, bits);
}

//F(op_: cd, compression str, level: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1compression(JNIEnv *jenv, jobject jobj, jobject op, jobject compression, jint level) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(compression);
    rnp_result_t ret = dlF(rnp_op_encrypt_set_compression)(cop, ccompression, level);
    ENCODE_FREE(compression);
    return ret;
}

//F(op_: cd, filename: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1file_1name(JNIEnv *jenv, jobject jobj, jobject op, jobject filename) {
    void *cop = Handle2Ptr(jenv, op);
    ENCODE_1STRING(filename);
    rnp_result_t ret = dlF(rnp_op_encrypt_set_file_name)(cop, cfilename);
    ENCODE_FREE(filename);
    return ret;
}

//F(op_: cd, mtime: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1set_1file_1mtime(JNIEnv *jenv, jobject jobj, jobject op, jlong mtime) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_encrypt_set_file_mtime)(cop, (uint32_t)mtime);
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1execute(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_encrypt_execute)(cop);
}

//F(op_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1op_1encrypt_1destroy(JNIEnv *jenv, jobject jobj, jobject op) {
    void *cop = Handle2Ptr(jenv, op);
    return dlF(rnp_op_encrypt_destroy)(cop);
}

//F(ffi: cd, input_: cd, output: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1decrypt(JNIEnv *jenv, jobject jobj, jobject ffi, jobject input, jobject output) {
    void *cffi = Handle2Ptr(jenv, ffi);
    void *cinput = Handle2Ptr(jenv, input);
    void *coutput = Handle2Ptr(jenv, output);
    return dlF(rnp_decrypt)(cffi, cinput, coutput);
}

//F(handle: cd, buf: [cd], buf_len: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1get_1public_1key_1data(JNIEnv *jenv, jobject jobj, jobject handle, jobject buf, jobject buf_len) {
    void *chandle = Handle2Ptr(jenv, handle);
    uint8_t *cbuf = NULL;
    size_t cbuf_len = 0;
    rnp_result_t ret = dlF(rnp_get_public_key_data)(chandle, CPTR(buf), CPTR(buf_len));
    AddHandle(jenv, buf, cbuf);
    AddLong(jenv, buf_len, cbuf_len);
    return ret;
}

//F(handle: cd, buf: [cd], buf_len: [int]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1get_1secret_1key_1data(JNIEnv *jenv, jobject jobj, jobject handle, jobject buf, jobject buf_len) {
    void *chandle = Handle2Ptr(jenv, handle);
    uint8_t *cbuf = NULL;
    size_t cbuf_len = 0;
    rnp_result_t ret = dlF(rnp_get_secret_key_data)(chandle, CPTR(buf), CPTR(buf_len));
    AddHandle(jenv, buf, cbuf);
    AddLong(jenv, buf_len, cbuf_len);
    return ret;
}

//F(handle: cd, flags: int, result: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1key_1to_1json(JNIEnv *jenv, jobject jobj, jobject handle, jint flags, jobject result) {
    void *chandle = Handle2Ptr(jenv, handle);
    char *cresult = NULL;
    rnp_result_t ret = dlF(rnp_key_to_json)(chandle, flags, CPTR(result));
    AddHandle(jenv, result, cresult);
    return ret;
}

//F(ffi: cd, it_: [cd], identifier_type: str) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1identifier_1iterator_1create(JNIEnv *jenv, jobject jobj, jobject ffi, jobject it, jobject identifier_type) {
    void *cffi = Handle2Ptr(jenv, ffi);
    rnp_identifier_iterator_t cit = NULL;
    ENCODE_1STRING(identifier_type);
    rnp_result_t ret = dlF(rnp_identifier_iterator_create)(cffi, CPTR(it), cidentifier_type);
    ENCODE_FREE(identifier_type);
    AddHandle(jenv, it, cit);
    return ret;
}

//F(it_: cd, identifier: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1identifier_1iterator_1next(JNIEnv *jenv, jobject jobj, jobject it, jobject identifier) {
    void *cit = Handle2Ptr(jenv, it);
    const char *cidentifier = NULL;
    rnp_result_t ret = dlF(rnp_identifier_iterator_next)(cit, CPTR(identifier));
    AddStrHandle(jenv, identifier, cidentifier);
    return ret;
}

//F(it_: cd) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1identifier_1iterator_1destroy(JNIEnv *jenv, jobject jobj, jobject it) {
    void *cit = Handle2Ptr(jenv, it);
    return dlF(rnp_identifier_iterator_destroy)(cit);
}

//F(input: cd, output: [cd]) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1pipe(JNIEnv *jenv, jobject jobj, jobject input, jobject output) {
    void *cinput = Handle2Ptr(jenv, input);
    void *coutput = Handle2Ptr(jenv, output);
    return dlF(rnp_output_pipe)(cinput, coutput);
}

//F(output: cd, llen: int) -> int
JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopLib_rnp_1output_1armor_1set_1line_1length(JNIEnv *jenv, jobject jobj, jobject output, long llen) {
    void *coutput = Handle2Ptr(jenv, output);
    return dlF(rnp_output_armor_set_line_length)(coutput, llen);
}

JNIEXPORT jobject JNICALL Java_tech_janky_jarop_rop_RopLib_native_1global_1ref(JNIEnv *jenv, jclass jcls, jobject jobj, jobject gref) {
    jobject newRef = NULL;
    void *cgref = NULL;
    if(gref != NULL)
        cgref = Handle2Ptr(jenv, gref);
    if(cgref != NULL) {
        (*jenv)->DeleteGlobalRef(jenv, cgref);
    } 
    if(gref == NULL && (*jenv)->ExceptionCheck(jenv) == JNI_FALSE) {
        newRef = (*jenv)->NewGlobalRef(jenv, jobj);
        if(jvm == NULL) {
            (*jenv)->GetJavaVM(jenv, &jvm);
            jniVer = (*jenv)->GetVersion(jenv);
        }
    }
    return AddHandle(jenv, NULL, newRef);
}


JNIEXPORT void JNICALL Java_tech_janky_jarop_rop_RopLib_nCleanUp(JNIEnv *jenv, jobject jobj) {
    const char* fldId[] = { "retainsI", "Ljava/util/TreeMap;", NULL };
    jfieldID fidRetI = FindJField(jenv, jobj, fldId, NULL);
    jobject retainsI = (fidRetI!=NULL? (*jenv)->GetObjectField(jenv, jobj, fidRetI) : NULL);
    if(retainsI != NULL) {
        const char* metId[] = { "pollLastEntry", "()Ljava/util/Map$Entry;", NULL };
        jmethodID midPollEnt = FindJMethod(jenv, retainsI, metId, NULL);
        if(midPollEnt != NULL) {
            jmethodID midKey = NULL;
            jobject entry;
            do {
                entry = (*jenv)->CallObjectMethod(jenv, retainsI, midPollEnt);
                if ((*jenv)->ExceptionCheck(jenv) == JNI_FALSE)
                    break;
                if(entry != NULL) {
                    if(midKey == NULL) {
                        const char* metId[] = { "getKey", "()Ljava/lang/Object;", NULL };
                        midKey = FindJMethod(jenv, entry, metId, NULL);
                        if(midKey == NULL)
                            break;
                    }
                    jobject key = (*jenv)->CallObjectMethod(jenv, entry, midKey);
                    if ((*jenv)->ExceptionCheck(jenv) == JNI_FALSE)
                        break;
                    SetHandle(jenv, retainsI, key, NULL);
                }
            } while(entry != NULL);
        }
    }
}


JNIEXPORT jstring JNICALL Java_tech_janky_jarop_rop_RopHandle_toString(JNIEnv *jenv, jobject jobj) {
    int type = 0;
    const char *str = Handle2PtrT(jenv, jobj, &type);
    if(type == 1)
        return str!=NULL? (*jenv)->NewStringUTF(jenv, str) : NULL;
    char buf[32];
    snprintf(buf, sizeof(buf), "%p", str);
    return (*jenv)->NewStringUTF(jenv, buf);
}

JNIEXPORT jobject JNICALL Java_tech_janky_jarop_rop_RopHandle_toBytes(JNIEnv *jenv, jobject jobj, jlong len) {
    const char *data = Handle2Ptr(jenv, jobj);
    jobject output = NULL;
    if(len == 0)
        len = strlen(data);
    if(data != NULL && len > 0) {
        output = (*jenv)->NewByteArray(jenv, (jsize)len);
        (*jenv)->SetByteArrayRegion(jenv, output, 0, (jsize)len, data);
    }
    return output;
}

JNIEXPORT jint JNICALL Java_tech_janky_jarop_rop_RopHandle_WriteString(JNIEnv *jenv, jobject jobj, jobject buf, jint maxLen) {
    jint len = 0;
    char *ptr = (char*)Handle2Ptr(jenv, jobj);
    ENCODE_1STRING(buf);
    strncpy(ptr, cbuf, maxLen);
    ptr[maxLen>1? maxLen-1 : 0] = '\0';
    ENCODE_FREE(buf);
    len = (jint)strlen(ptr);
    return len;
}

JNIEXPORT jlong JNICALL Java_tech_janky_jarop_rop_RopHandle_WriteBytes(JNIEnv *jenv, jobject jobj, jobject buf, jlong len) {
    char *ptr = (char*)Handle2Ptr(jenv, jobj);
    (*jenv)->GetByteArrayRegion(jenv, buf, 0, (jsize)len, ptr);
    return len;
}

JNIEXPORT void JNICALL Java_tech_janky_jarop_rop_RopHandle_ClearMemory(JNIEnv *jenv, jobject jobj, jlong len) {
    void *ptr = Handle2Ptr(jenv, jobj);
    dlF(rnp_buffer_clear)(ptr, len>=0? (size_t)len : strlen(ptr));
}

static void key_callback(rnp_ffi_t ffi, void *app_ctx, const char *identifier_type, const char *identifier, bool secret) {
    if(app_ctx == NULL)
        return;
    JNIEnv *jenv = NULL;
    jint jeStat = AttachToVM(&jenv);

    jobject jffi = AddHandle(jenv, NULL, ffi);
    jobject jidentifier_type = AddHandle(jenv, NULL, identifier_type);
    jobject jidentifier = AddHandle(jenv, NULL, identifier);
    const char *metId[] = {"KeyCB", "(Ltech/janky/jarop/rop/RopHandle;Ltech/janky/jarop/rop/RopHandle;Ltech/janky/jarop/rop/RopHandle;Z)V"};
    jmethodID midCB = FindJMethod(jenv, (jobject)app_ctx, metId, NULL);
    if(midCB != NULL)
        (*jenv)->CallVoidMethod(jenv, app_ctx, midCB, jffi, jidentifier_type, jidentifier, secret);
    DettachFromVM(jenv, jeStat);
}

static bool pass_callback(rnp_ffi_t ffi, void *app_ctx, rnp_key_handle_t key, const char *pgp_context, char buf[], size_t buf_len) {
    if(app_ctx == NULL)
        return false;
    jboolean ret = false;
    JNIEnv *jenv = NULL;
    jint jeStat = AttachToVM(&jenv);

    jobject jffi = AddHandle(jenv, NULL, ffi);
    jobject jkey = AddHandle(jenv, NULL, key);
    jobject jpgp_context = AddHandle(jenv, NULL, pgp_context);
    jobject jbuf = AddHandle(jenv, NULL, buf);
    const char *metId[] = {"PassCB", "(Ltech/janky/jarop/rop/RopHandle;Ltech/janky/jarop/rop/RopHandle;Ltech/janky/jarop/rop/RopHandle;Ltech/janky/jarop/rop/RopHandle;I)Z"};
    jmethodID midCB = FindJMethod(jenv, (jobject)app_ctx, metId, NULL);
    if(midCB != NULL)
        ret = (*jenv)->CallBooleanMethod(jenv, app_ctx, midCB, jffi, jkey, jpgp_context, jbuf, buf_len);
    DettachFromVM(jenv, jeStat);
    return ret;
}

static bool input_read_callback(void *app_ctx, void *buf, size_t len, size_t *read) {
    if(app_ctx == NULL)
        return 0;
    jlong ret = 0;
    JNIEnv *jenv = NULL;
    jint jeStat = AttachToVM(&jenv);

    jobject jbuf = AddHandle(jenv, NULL, buf);
    const char *metId[] = {"InReadCB", "(Ltech/janky/jarop/rop/RopHandle;J)J"};
    jmethodID midCB = FindJMethod(jenv, (jobject)app_ctx, metId, NULL);
    if(midCB != NULL)
        ret = (*jenv)->CallLongMethod(jenv, app_ctx, midCB, jbuf, len);
    DettachFromVM(jenv, jeStat);
    if(read != NULL)
        *read = (size_t)ret;
    return ret>=0;
}

static void input_close_callback(void *app_ctx) {
    if(app_ctx == NULL)
        return;
    JNIEnv *jenv = NULL;
    jint jeStat = AttachToVM(&jenv);

    const char *metId[] = {"InCloseCB", "()V"};
    jmethodID midCB = FindJMethod(jenv, (jobject)app_ctx, metId, NULL);
    if(midCB != NULL)
        (*jenv)->CallVoidMethod(jenv, app_ctx, midCB);
    DettachFromVM(jenv, jeStat);
}

static bool output_write_callback(void *app_ctx, const void *buf, size_t len) {
    if(app_ctx == NULL)
        return false;
    jboolean ret = false;
    JNIEnv *jenv = NULL;
    jint jeStat = AttachToVM(&jenv);

    jobject jbuf = AddHandle(jenv, NULL, buf);
    if ((*jenv)->ExceptionCheck(jenv) == JNI_FALSE) {
        const char *metId[] = {"OutWriteCB", "(Ltech/janky/jarop/rop/RopHandle;J)Z"};
        jmethodID midCB = FindJMethod(jenv, (jobject)app_ctx, metId, NULL);
        if(midCB != NULL)
            ret = (*jenv)->CallBooleanMethod(jenv, app_ctx, midCB, jbuf, len);
    }
    DettachFromVM(jenv, jeStat);
    return ret;
}

static void output_close_callback(void *app_ctx, bool discard) {
    if(app_ctx == NULL)
        return;
    JNIEnv *jenv = NULL;
    jint jeStat = AttachToVM(&jenv);

    const char *metId[] = {"OutCloseCB", "(Z)V"};
    jmethodID midCB = FindJMethod(jenv, (jobject)app_ctx, metId, NULL);
    if(midCB != NULL)
        (*jenv)->CallVoidMethod(jenv, app_ctx, midCB, discard);
    DettachFromVM(jenv, jeStat);
}


void on_attach();

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    if(jvm == NULL) {
        jvm = vm;
        JNIEnv *jenv = NULL;
        (*jvm)->GetEnv(jvm, (void**)&jenv, JNI_VERSION_1_8);
        jniVer = (*jenv)->GetVersion(jenv);
        on_attach();
    }
    return JNI_VERSION_1_8;
}

static void ThrowException(const char *exClsName, const char *msg, const char* symbol, const char* err) {
    JNIEnv *jenv = NULL;
    jint jeStat = AttachToVM(&jenv);
    jclass hndCls = (*jenv)->FindClass(jenv, exClsName);
    if(hndCls != NULL) {
        char buf[0x100];
        snprintf(buf, sizeof(buf)-1, msg, symbol);
        if(err != NULL) {
            size_t len = strlen(buf);
            snprintf(buf+len, sizeof(buf)-len-1, " (%s)", err);
        }
        buf[sizeof(buf)-1] = '\0';
        (*jenv)->ThrowNew(jenv, hndCls, buf);
    }
    DettachFromVM(jenv, jeStat);
}

void ThrowMissingLibrary(const char* libName, const char* err) {
    ThrowException("java/lang/InstantiationError", "Loading '%s' failed!", libName, err);
}

void ThrowMissingMethod(const char* metName, const char* err) {
    ThrowException("java/lang/NoSuchMethodException", "Method '%s' is missing!", metName, err);
}

#ifdef __cplusplus
}
#endif
