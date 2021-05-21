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

#ifndef ROP_LIB_DYN_LOAD_H
#define ROP_LIB_DYN_LOAD_H

#define SCRWD_P /* BE AWARE */

#ifndef PRINTFLIKE
#define PRINTFLIKE(n, m)
#endif

#if defined(_WIN32) && defined(_MSC_VER)
typedef long long ssize_t;
#endif
#include <rnp/rnp_def.h>
#include <rnp/rnp.h>


#ifdef __cplusplus
extern "C" {
#endif

#ifdef ROP_LOAD_STATIC
    void ROP_load();
    void ROP_unload();
#endif

#define dlF(n) dl_##n
#define CALL dlF

#ifndef ROP_DYN_IMPORT

#define ROP_DYN_IMPORT0(r, d, n) r dlF(n)()
#define ROP_DYN_IMPORT1(r, d, n, p1) r dlF(n)(p1)
#define ROP_DYN_IMPORT2(r, d, n, p1, p2) r dlF(n)(p1, p2)
#define ROP_DYN_IMPORT3(r, d, n, p1, p2, p3) r dlF(n)(p1, p2, p3)
#define ROP_DYN_IMPORT4(r, d, n, p1, p2, p3, p4) r dlF(n)(p1, p2, p3, p4)
#define ROP_DYN_IMPORT5(r, d, n, p1, p2, p3, p4, p5) r dlF(n)(p1, p2, p3, p4, p5)
#define ROP_DYN_IMPORT6(r, d, n, p1, p2, p3, p4, p5, p6) r dlF(n)(p1, p2, p3, p4, p5, p6)
#define ROP_DYN_IMPORT10(r, d, n, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10) r dlF(n)(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10)

#endif // ROP_DYN_IMPORT


ROP_DYN_IMPORT1(const char *, NULL, rnp_result_to_string, rnp_result_t);
ROP_DYN_IMPORT0(const char *, NULL, rnp_version_string);
ROP_DYN_IMPORT0(const char *, NULL, rnp_version_string_full);
ROP_DYN_IMPORT0(uint32_t, -1, rnp_version SCRWD_P);
ROP_DYN_IMPORT3(uint32_t, -1, rnp_version_for, uint32_t, uint32_t, uint32_t);
ROP_DYN_IMPORT1(uint32_t, -1, rnp_version_major, uint32_t);
ROP_DYN_IMPORT1(uint32_t, -1, rnp_version_minor, uint32_t);
ROP_DYN_IMPORT1(uint32_t, -1, rnp_version_patch, uint32_t);
ROP_DYN_IMPORT0(uint64_t, 0, rnp_version_commit_timestamp);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_enable_debug, const char *);
ROP_DYN_IMPORT0(rnp_result_t, -1, rnp_disable_debug);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_ffi_create, rnp_ffi_t *, const char *, const char *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_ffi_destroy, rnp_ffi_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_ffi_set_log_fd, rnp_ffi_t, int);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_ffi_set_key_provider, rnp_ffi_t, rnp_get_key_cb, void *);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_ffi_set_pass_provider, rnp_ffi_t, rnp_password_cb, void *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_get_default_homedir, char **);
ROP_DYN_IMPORT5(
rnp_result_t, -1, rnp_detect_homedir_info, const char *, char **, char **, char **, char **);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_detect_key_format, const uint8_t *, size_t, char **);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_calculate_iterations, const char *, size_t, size_t *);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_supports_feature, const char *, const char *, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_supported_features, const char *, char **);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_request_password, rnp_ffi_t, rnp_key_handle_t, const char*, char**);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_load_keys, rnp_ffi_t, const char *, rnp_input_t, uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_unload_keys, rnp_ffi_t, uint32_t);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_import_keys, rnp_ffi_t, rnp_input_t, uint32_t, char **);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_import_signatures, rnp_ffi_t, rnp_input_t, uint32_t, char**);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_save_keys, rnp_ffi_t, const char *, rnp_output_t, uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_get_public_key_count, rnp_ffi_t, size_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_get_secret_key_count, rnp_ffi_t, size_t *);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_locate_key, rnp_ffi_t, const char *, const char *, rnp_key_handle_t *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_key_handle_destroy, rnp_key_handle_t);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_generate_key_json, rnp_ffi_t, const char *, char **);
ROP_DYN_IMPORT6(rnp_result_t, -1,
                    rnp_generate_key_rsa,
                    rnp_ffi_t,
                    uint32_t,
                    uint32_t,
                    const char *,
                    const char *,
                    rnp_key_handle_t *);
ROP_DYN_IMPORT6(rnp_result_t, -1,
                    rnp_generate_key_dsa_eg,
                    rnp_ffi_t,
                    uint32_t,
                    uint32_t,
                    const char *,
                    const char *,
                    rnp_key_handle_t *);
ROP_DYN_IMPORT5(rnp_result_t, -1,
                    rnp_generate_key_ec,
                    rnp_ffi_t,
                    const char *,
                    const char *,
                    const char *,
                    rnp_key_handle_t *);
ROP_DYN_IMPORT4(rnp_result_t, -1,
                    rnp_generate_key_25519,
                    rnp_ffi_t,
                    const char *,
                    const char *,
                    rnp_key_handle_t *);
ROP_DYN_IMPORT4(rnp_result_t, -1,
                    rnp_generate_key_sm2,
                    rnp_ffi_t,
                    const char *,
                    const char *,
                    rnp_key_handle_t *);
ROP_DYN_IMPORT10(rnp_result_t, -1,
                    rnp_generate_key_ex,
                    rnp_ffi_t,
                    const char *,
                    const char *,
                    uint32_t,
                    uint32_t,
                    const char *,
                    const char *,
                    const char *,
                    const char *,
                    rnp_key_handle_t *);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_op_generate_create, rnp_op_generate_t *, rnp_ffi_t, const char *);
ROP_DYN_IMPORT4(rnp_result_t, -1,
                    rnp_op_generate_subkey_create,
                    rnp_op_generate_t *,
                    rnp_ffi_t,
                    rnp_key_handle_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_generate_set_bits, rnp_op_generate_t, uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_generate_set_hash, rnp_op_generate_t, const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_dsa_qbits,
                    rnp_op_generate_t,
                    uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_curve,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_protection_password,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_request_password,
                    rnp_op_generate_t,
                    bool);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_protection_cipher,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_protection_hash,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_protection_mode,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_protection_iterations,
                    rnp_op_generate_t,
                    uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_add_usage,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_generate_clear_usage, rnp_op_generate_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_userid,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_expiration,
                    rnp_op_generate_t,
                    uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_add_pref_hash,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_generate_clear_pref_hashes, rnp_op_generate_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_add_pref_compression,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_generate_clear_pref_compression, rnp_op_generate_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_add_pref_cipher,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_generate_clear_pref_ciphers, rnp_op_generate_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_set_pref_keyserver,
                    rnp_op_generate_t,
                    const char *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_generate_execute, rnp_op_generate_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_generate_get_key,
                    rnp_op_generate_t,
                    rnp_key_handle_t *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_generate_destroy, rnp_op_generate_t);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_key_export, rnp_key_handle_t, rnp_output_t, uint32_t);
ROP_DYN_IMPORT5(rnp_result_t, -1, rnp_key_export_autocrypt, rnp_key_handle_t, rnp_key_handle_t, const char *, rnp_output_t, uint32_t);
ROP_DYN_IMPORT6(rnp_result_t, -1, rnp_key_export_revocation, rnp_key_handle_t, rnp_output_t, uint32_t, const char*, const char*, const char*);
ROP_DYN_IMPORT5(rnp_result_t, -1, rnp_key_revoke, rnp_key_handle_t, uint32_t, const char*, const char*, const char*);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_remove, rnp_key_handle_t, uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_guess_contents, rnp_input_t, char **);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_enarmor, rnp_input_t, rnp_output_t, const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_dearmor, rnp_input_t, rnp_output_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_primary_uid, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_uid_count, rnp_key_handle_t, size_t *);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_key_get_uid_at, rnp_key_handle_t, size_t, char **);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_key_get_uid_handle_at, rnp_key_handle_t, size_t, rnp_uid_handle_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_uid_get_type, rnp_uid_handle_t, uint32_t *);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_uid_get_data, rnp_uid_handle_t, void **, size_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_uid_is_primary, rnp_uid_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_uid_is_valid, rnp_uid_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_signature_count, rnp_key_handle_t, size_t *);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_key_get_signature_at, rnp_key_handle_t, size_t, rnp_signature_handle_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_revocation_signature, rnp_key_handle_t, rnp_signature_handle_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_uid_get_signature_count, rnp_uid_handle_t, size_t *);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_uid_get_signature_at, rnp_uid_handle_t, size_t, rnp_signature_handle_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_signature_get_type, rnp_signature_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_signature_get_alg, rnp_signature_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_signature_get_hash_alg,
                    rnp_signature_handle_t,
                    char **);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_signature_get_creation,
                    rnp_signature_handle_t,
                    uint32_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_signature_get_keyid, rnp_signature_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_signature_get_signer,
                    rnp_signature_handle_t,
                    rnp_key_handle_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_signature_is_valid, rnp_signature_handle_t, uint32_t);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_signature_packet_to_json, rnp_signature_handle_t, uint32_t, char **);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_signature_handle_destroy, rnp_signature_handle_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_uid_is_revoked, rnp_uid_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_uid_get_revocation_signature, rnp_uid_handle_t, rnp_signature_handle_t *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_uid_handle_destroy, rnp_uid_handle_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_subkey_count, rnp_key_handle_t, size_t *);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_key_get_subkey_at, rnp_key_handle_t, size_t, rnp_key_handle_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_alg, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_bits, rnp_key_handle_t, uint32_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_dsa_qbits, rnp_key_handle_t, uint32_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_curve, rnp_key_handle_t, char **);
ROP_DYN_IMPORT6(rnp_result_t, -1,
                    rnp_key_add_uid,
                    rnp_key_handle_t,
                    const char *,
                    const char *,
                    uint32_t,
                    uint8_t,
                    bool);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_fprint, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_keyid, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_grip, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_primary_grip, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_primary_fprint, rnp_key_handle_t, char **);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_key_allows_usage, rnp_key_handle_t, const char *, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_creation, rnp_key_handle_t, uint32_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_expiration, rnp_key_handle_t, uint32_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_set_expiration, rnp_key_handle_t, uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_is_valid, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_valid_till, rnp_key_handle_t, uint32_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_is_revoked, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_revocation_reason, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_is_superseded, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_is_compromised, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_is_retired, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_is_locked, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_protection_type, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_protection_mode, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_protection_cipher, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_protection_hash, rnp_key_handle_t, char **);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_get_protection_iterations, rnp_key_handle_t, size_t *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_key_lock, rnp_key_handle_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_unlock, rnp_key_handle_t, const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_is_protected, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT6(rnp_result_t, -1,
                    rnp_key_protect,
                    rnp_key_handle_t,
                    const char *,
                    const char *,
                    const char *,
                    const char *,
                    size_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_unprotect, rnp_key_handle_t, const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_is_primary, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_is_sub, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_have_secret, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_key_have_public, rnp_key_handle_t, bool *);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_key_packets_to_json, rnp_key_handle_t, bool, uint32_t, char **);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_dump_packets_to_json, rnp_input_t, uint32_t, char **);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_dump_packets_to_output, rnp_input_t, rnp_output_t, uint32_t);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_op_sign_create, rnp_op_sign_t *, rnp_ffi_t, rnp_input_t, rnp_output_t);
ROP_DYN_IMPORT4(rnp_result_t, -1,
                    rnp_op_sign_cleartext_create,
                    rnp_op_sign_t *,
                    rnp_ffi_t,
                    rnp_input_t,
                    rnp_output_t);
ROP_DYN_IMPORT4(rnp_result_t, -1,
                    rnp_op_sign_detached_create,
                    rnp_op_sign_t *,
                    rnp_ffi_t,
                    rnp_input_t,
                    rnp_output_t);
ROP_DYN_IMPORT3(rnp_result_t, -1,
                    rnp_op_sign_add_signature,
                    rnp_op_sign_t,
                    rnp_key_handle_t,
                    rnp_op_sign_signature_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_sign_signature_set_hash,
                    rnp_op_sign_signature_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_sign_signature_set_creation_time,
                    rnp_op_sign_signature_t,
                    uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_sign_signature_set_expiration_time,
                    rnp_op_sign_signature_t,
                    uint32_t);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_op_sign_set_compression, rnp_op_sign_t, const char *, int);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_sign_set_armor, rnp_op_sign_t, bool);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_sign_set_hash, rnp_op_sign_t, const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_sign_set_creation_time, rnp_op_sign_t, uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_sign_set_expiration_time, rnp_op_sign_t, uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_sign_set_file_name, rnp_op_sign_t, const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_sign_set_file_mtime, rnp_op_sign_t, uint32_t);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_sign_execute, rnp_op_sign_t);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_sign_destroy, rnp_op_sign_t);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_op_verify_create, rnp_op_verify_t *, rnp_ffi_t, rnp_input_t, rnp_output_t);
ROP_DYN_IMPORT4(rnp_result_t, -1,
                    rnp_op_verify_detached_create,
                    rnp_op_verify_t *,
                    rnp_ffi_t,
                    rnp_input_t,
                    rnp_input_t);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_verify_execute, rnp_op_verify_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_verify_get_signature_count,
                    rnp_op_verify_t,
                    size_t *);
ROP_DYN_IMPORT3(rnp_result_t, -1,
                    rnp_op_verify_get_signature_at,
                    rnp_op_verify_t,
                    size_t,
                    rnp_op_verify_signature_t *);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_op_verify_get_file_info, rnp_op_verify_t, char **, uint32_t *);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_op_verify_get_protection_info, rnp_op_verify_t, char**, char**, bool*);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_op_verify_get_recipient_count, rnp_op_verify_t, size_t*);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_op_verify_get_used_recipient, rnp_op_verify_t, rnp_recipient_handle_t*);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_op_verify_get_recipient_at, rnp_op_verify_t, size_t, rnp_recipient_handle_t*);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_op_verify_get_symenc_count, rnp_op_verify_t, size_t*);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_op_verify_get_used_symenc, rnp_op_verify_t, rnp_symenc_handle_t*);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_op_verify_get_symenc_at, rnp_op_verify_t, size_t, rnp_symenc_handle_t*);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_recipient_get_keyid, rnp_recipient_handle_t, char**);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_recipient_get_alg, rnp_recipient_handle_t, char**);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_symenc_get_cipher, rnp_symenc_handle_t, char**);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_symenc_get_aead_alg, rnp_symenc_handle_t, char**);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_symenc_get_hash_alg, rnp_symenc_handle_t, char**);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_symenc_get_s2k_type, rnp_symenc_handle_t, char**);
ROP_DYN_IMPORT2(
rnp_result_t, -1, rnp_symenc_get_s2k_iterations, rnp_symenc_handle_t, uint32_t*);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_verify_destroy, rnp_op_verify_t);
ROP_DYN_IMPORT1(rnp_result_t, -1,
                    rnp_op_verify_signature_get_status,
                    rnp_op_verify_signature_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_verify_signature_get_handle,
                    rnp_op_verify_signature_t,
                    rnp_signature_handle_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_verify_signature_get_hash,
                    rnp_op_verify_signature_t,
                    char **);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_verify_signature_get_key,
                    rnp_op_verify_signature_t,
                    rnp_key_handle_t *);
ROP_DYN_IMPORT3(rnp_result_t, -1,
                    rnp_op_verify_signature_get_times,
                    rnp_op_verify_signature_t,
                    uint32_t *,
                    uint32_t *);
ROP_DYN_IMPORT1(int, 0, rnp_buffer_destroy, void *);
ROP_DYN_IMPORT2(void, 0, rnp_buffer_clear, void*, size_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_input_from_path, rnp_input_t *, const char *);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_input_from_memory, rnp_input_t *, const uint8_t *, size_t, bool);
ROP_DYN_IMPORT4(rnp_result_t, -1,
                    rnp_input_from_callback,
                    rnp_input_t *,
                    rnp_input_reader_t *,
                    rnp_input_closer_t *,
                    void *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_input_destroy, rnp_input_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_output_to_path, rnp_output_t *, const char *);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_output_to_file, rnp_output_t *, const char *, uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_output_to_memory, rnp_output_t *, size_t);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_output_to_armor, rnp_output_t, rnp_output_t *, const char *);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_output_memory_get_buf, rnp_output_t, uint8_t **, size_t *, bool);
ROP_DYN_IMPORT4(rnp_result_t, -1,
                    rnp_output_to_callback,
                    rnp_output_t *,
                    rnp_output_writer_t *,
                    rnp_output_closer_t *,
                    void *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_output_to_null, rnp_output_t *);
ROP_DYN_IMPORT4(
rnp_result_t, -1, rnp_output_write, rnp_output_t, const void *, size_t, size_t *);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_output_finish, rnp_output_t);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_output_destroy, rnp_output_t);
ROP_DYN_IMPORT4(rnp_result_t, -1,
                    rnp_op_encrypt_create,
                    rnp_op_encrypt_t *,
                    rnp_ffi_t,
                    rnp_input_t,
                    rnp_output_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_encrypt_add_recipient,
                    rnp_op_encrypt_t,
                    rnp_key_handle_t);
ROP_DYN_IMPORT3(rnp_result_t, -1,
                    rnp_op_encrypt_add_signature,
                    rnp_op_encrypt_t,
                    rnp_key_handle_t,
                    rnp_op_sign_signature_t *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_encrypt_set_hash, rnp_op_encrypt_t, const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_encrypt_set_creation_time,
                    rnp_op_encrypt_t,
                    uint32_t);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_encrypt_set_expiration_time,
                    rnp_op_encrypt_t,
                    uint32_t);
ROP_DYN_IMPORT5(rnp_result_t, -1,
                    rnp_op_encrypt_add_password,
                    rnp_op_encrypt_t,
                    const char *,
                    const char *,
                    size_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_encrypt_set_armor, rnp_op_encrypt_t, bool);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_encrypt_set_cipher, rnp_op_encrypt_t, const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_encrypt_set_aead, rnp_op_encrypt_t, const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_encrypt_set_aead_bits, rnp_op_encrypt_t, int);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_op_encrypt_set_compression, rnp_op_encrypt_t, const char *, int);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_op_encrypt_set_file_name,
                    rnp_op_encrypt_t,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_op_encrypt_set_file_mtime, rnp_op_encrypt_t, uint32_t);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_encrypt_execute, rnp_op_encrypt_t);
ROP_DYN_IMPORT1(rnp_result_t, -1, rnp_op_encrypt_destroy, rnp_op_encrypt_t);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_decrypt, rnp_ffi_t, rnp_input_t, rnp_output_t);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_get_public_key_data, rnp_key_handle_t, uint8_t **, size_t *);
ROP_DYN_IMPORT3(
rnp_result_t, -1, rnp_get_secret_key_data, rnp_key_handle_t, uint8_t **, size_t *);
ROP_DYN_IMPORT3(rnp_result_t, -1, rnp_key_to_json, rnp_key_handle_t, uint32_t, char **);
ROP_DYN_IMPORT3(rnp_result_t, -1,
                    rnp_identifier_iterator_create,
                    rnp_ffi_t,
                    rnp_identifier_iterator_t *,
                    const char *);
ROP_DYN_IMPORT2(rnp_result_t, -1,
                    rnp_identifier_iterator_next,
                    rnp_identifier_iterator_t,
                    const char **);
ROP_DYN_IMPORT1(rnp_result_t, -1,
                    rnp_identifier_iterator_destroy,
                    rnp_identifier_iterator_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_output_pipe, rnp_input_t, rnp_output_t);
ROP_DYN_IMPORT2(rnp_result_t, -1, rnp_output_armor_set_line_length, rnp_output_t, size_t);

#ifdef __cplusplus

#define HCAST_FFI(hnd) static_cast<rnp_ffi_t>(hnd)
#define HCAST_INP(hnd) static_cast<rnp_input_t>(hnd)
#define HCAST_OUTP(hnd) static_cast<rnp_output_t>(hnd)
#define HCAST_KEY(hnd) static_cast<rnp_key_handle_t>(hnd)
#define HCAST_UID(hnd) static_cast<rnp_uid_handle_t>(hnd)
#define HCAST_SIG(hnd) static_cast<rnp_signature_handle_t>(hnd)
#define HCAST_OPSSN(hnd) static_cast<rnp_op_sign_signature_t>(hnd)
#define HCAST_OPSIG(hnd) static_cast<rnp_op_sign_t>(hnd)
#define HCAST_OPGEN(hnd) static_cast<rnp_op_generate_t>(hnd)
#define HCAST_OPENC(hnd) static_cast<rnp_op_encrypt_t>(hnd)
#define HCAST_OPVER(hnd) static_cast<rnp_op_verify_t>(hnd)
#define HCAST_OPVES(hnd) static_cast<rnp_op_verify_signature_t>(hnd)
#define HCAST_RECIP(hnd) static_cast<rnp_recipient_handle_t>(hnd)
#define HCAST_SENC(hnd) static_cast<rnp_symenc_handle_t>(hnd)
#define HCAST_IDIT(hnd) static_cast<rnp_identifier_iterator_t>(hnd)

#endif

#ifdef __cplusplus
}
#endif

#endif // ROP_LIB_DYN_LOAD_H
