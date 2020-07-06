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

package tech.janky.jarop.rop;

import java.util.TreeMap;
import java.util.Vector;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.net.URI;


/**
* @version 0.3.0
* @since   0.2
*/
public class RopLib {
    public RopLib() {
        retainsI = new TreeMap<RopHandle, RopHandle>();
        h2cb = new TreeMap<RopHandle, RopCB[]>();
    }

    public int RetCounts() {
        return retainsI.size();
    }

    public void CleanUp() {
        for(RopHandle hnd : h2cb.keySet())
            ClearCallbacks(hnd);
                nCleanUp();
    }

    public int rnp_ffi_destroy(RopHandle ffi) {
        int ret = nrnp_ffi_destroy(ffi);
        ClearCallbacks(ffi);
        return ret;
    }

    public int rnp_ffi_set_key_provider(RopHandle ffi, RopKeyCallBack getkeycb, Object getkeycb_ctx) {
        RopCB cb = getkeycb!=null? new RopCB(RopCB.Type.KEY, ffi, getkeycb_ctx, getkeycb) : null;
        if(cb != null)
            cb.nhnd = RopLib.native_global_ref(cb, null);
        int ret = nrnp_ffi_set_key_provider(ffi, cb!=null? cb.nhnd : null);
        if(cb != null) {
            RopCB[] cbs = (RopCB[])h2cb.get(ffi);
            if(cbs == null) {
                cbs = new RopCB[2];
                h2cb.put(ffi, cbs);
            }
            cbs[0] = cb;
        }
        return ret;
    }

    public int rnp_ffi_set_pass_provider(RopHandle ffi, RopPassCallBack getpasscb, Object getpasscb_ctx) {
        RopCB cb = getpasscb!=null? new RopCB(RopCB.Type.PASS, ffi, getpasscb_ctx, getpasscb) : null;
        if(cb != null)
            cb.nhnd = RopLib.native_global_ref(cb, null);
        int ret = nrnp_ffi_set_pass_provider(ffi, cb!=null? cb.nhnd : null);
        if(cb != null) {
            RopCB[] cbs = (RopCB[])h2cb.get(ffi);
            if(cbs == null) {
                cbs = new RopCB[2];
                h2cb.put(ffi, cbs);
            }
            cbs[1] = cb;
        }
        return ret;
    }

    public int rnp_input_from_callback(Vector<?> input, RopInputCallBack callBack, Object app_ctx) {
        RopCB icb = callBack!=null? new RopCB(RopCB.Type.INPUT, null, app_ctx, callBack) : null;
        RopHandle nicb = icb!=null? RopLib.native_global_ref(icb, null) : null;
        int ret = nrnp_input_from_callback(input, nicb);
        if(icb != null) {
            RopHandle inp = (RopHandle)input.lastElement();
            if(inp != null && !inp.isNull()) {
                icb.hnd = inp;
                icb.nhnd = nicb;
                h2cb.put(inp, new RopCB[] {icb});
            }
        }
        return ret;
    }

    public int rnp_input_destroy(RopHandle input) {
        int ret = nrnp_input_destroy(input);
        ClearCallbacks(input);
        return ret;
    }

    public int rnp_output_to_callback(Vector<?> output, RopOutputCallBack callBack, Object app_ctx) {
        RopCB ocb = callBack!=null? new RopCB(RopCB.Type.OUTPUT, null, app_ctx, callBack) : null;
        RopHandle nocb = ocb!=null? RopLib.native_global_ref(ocb, null) : null;
        int ret = nrnp_output_to_callback(output, nocb);
        if(ocb != null) {
            RopHandle outp = (RopHandle)output.lastElement();
            if(outp != null && !outp.isNull()) {
                ocb.hnd = outp;
                ocb.nhnd = nocb;
                h2cb.put(outp, new RopCB[] {ocb});
            }
        }
        return ret;
    }

    public int rnp_output_destroy(RopHandle output) {
        int ret = nrnp_output_destroy(output);
        ClearCallbacks(output);
        return ret;
    }

    public native String rnp_result_to_string(int result);
    public native String rnp_version_string(); 
    public native String rnp_version_string_full(); 
    public native int rnp_version(); 
    public native int rnp_version_for(int major, int minor, int patch); 
    public native int rnp_version_major(int version); 
    public native int rnp_version_minor(int version); 
    public native int rnp_version_patch(int version); 
    public native long rnp_version_commit_timestamp(); 
    public native int rnp_enable_debug(String file); 
    public native int rnp_disable_debug(); 
    public native int rnp_ffi_create(Vector<?> ffi, String pub_format, String sec_format);
    public native int rnp_ffi_set_log_fd(RopHandle ffi, int fd);
    public native int rnp_get_default_homedir(Vector<?> homedir);
    public native int rnp_detect_homedir_info(Object homedir, Vector<?> pub_format, Vector<?> pub_path, Vector<?> sec_format, Vector<?> sec_path);
    public native int rnp_detect_key_format(Object buf, long buf_len, Vector<?> format);
    public native int rnp_calculate_iterations(Object hash, long msec, Vector<?> iterations); 
    public native int rnp_supports_feature(Object type, Object name, Vector<?> supported); 
    public native int rnp_supported_features(Object type, Vector<?> result);
    public native int rnp_request_password(RopHandle ffi, RopHandle key, Object context, Vector<?> password);
    public native int rnp_load_keys(RopHandle ffi, Object format, RopHandle input, int flags);
    public native int rnp_unload_keys(RopHandle ffi, int flags);
    public native int rnp_import_keys(RopHandle ffi, RopHandle input, int flags, Vector<?> results);
    public native int rnp_import_signatures(RopHandle ffi, RopHandle input, int flags, Vector<?> results);
    public native int rnp_save_keys(RopHandle ffi, Object format, RopHandle output, int flags);
    public native int rnp_get_public_key_count(RopHandle ffi, Vector<?> count);
    public native int rnp_get_secret_key_count(RopHandle ffi, Vector<?> count);
    public native int rnp_locate_key(RopHandle ffi, Object identifier_type, Object identifier, Vector<?> key);
    public native int rnp_key_handle_destroy(RopHandle key);
    public native int rnp_generate_key_json(RopHandle ffi, Object json, Vector<?> results);
    public native int rnp_generate_key_rsa(RopHandle ffi, int bits, int subbits, Object userid, Object password, Vector<?> key);
    public native int rnp_generate_key_dsa_eg(RopHandle ffi, int bits, int subbits, Object userid, Object password, Vector<?> key);
    public native int rnp_generate_key_ec(RopHandle ffi, Object curve, Object userid, Object password, Vector<?> key);
    public native int rnp_generate_key_25519(RopHandle ffi, Object userid, Object password, Vector<?> key);
    public native int rnp_generate_key_sm2(RopHandle ffi, Object userid, Object password, Vector<?> key);
    public native int rnp_generate_key_ex(RopHandle ffi, Object key_alg, Object sub_alg, int key_bits, int sub_bits, Object key_curve, Object sub_curve, Object userid, Object password, Vector<?> key);
    public native int rnp_op_generate_create(Vector<?> op, RopHandle ffi, Object alg);
    public native int rnp_op_generate_subkey_create(Vector<?> op, RopHandle ffi, RopHandle primary, Object alg);
    public native int rnp_op_generate_set_bits(RopHandle op, int bits);
    public native int rnp_op_generate_set_hash(RopHandle op, Object hash);
    public native int rnp_op_generate_set_dsa_qbits(RopHandle op, int qbits);
    public native int rnp_op_generate_set_curve(RopHandle op, Object curve);
    public native int rnp_op_generate_set_protection_password(RopHandle op, Object password);
    public native int rnp_op_generate_set_request_password(RopHandle op, boolean request);
    public native int rnp_op_generate_set_protection_cipher(RopHandle op, Object cipher);
    public native int rnp_op_generate_set_protection_hash(RopHandle op, Object hash);
    public native int rnp_op_generate_set_protection_mode(RopHandle op, Object mode);
    public native int rnp_op_generate_set_protection_iterations(RopHandle op, int iterations);
    public native int rnp_op_generate_add_usage(RopHandle op, Object usage);
    public native int rnp_op_generate_clear_usage(RopHandle op);
    public native int rnp_op_generate_set_userid(RopHandle op, Object userid);
    public native int rnp_op_generate_set_expiration(RopHandle op, long expiration);
    public native int rnp_op_generate_add_pref_hash(RopHandle op, Object hash);
    public native int rnp_op_generate_clear_pref_hashes(RopHandle op);
    public native int rnp_op_generate_add_pref_compression(RopHandle op, Object compression);
    public native int rnp_op_generate_clear_pref_compression(RopHandle op);
    public native int rnp_op_generate_add_pref_cipher(RopHandle op, Object cipher);
    public native int rnp_op_generate_clear_pref_ciphers(RopHandle op);
    public native int rnp_op_generate_set_pref_keyserver(RopHandle op, Object keyserver);
    public native int rnp_op_generate_execute(RopHandle op);
    public native int rnp_op_generate_get_key(RopHandle op, Vector<?> handle);
    public native int rnp_op_generate_destroy(RopHandle op);
    public native int rnp_key_export(RopHandle key, RopHandle output, int flags);
    public native int rnp_key_export_revocation(RopHandle key, RopHandle output, int flags, Object hash, Object code, Object reason);
    public native int rnp_key_revoke(RopHandle key, int flags, Object hash, Object code, Object reason);
    public native int rnp_key_remove(RopHandle key, int flags);
    public native int rnp_guess_contents(RopHandle input, Vector<?> contents);
    public native int rnp_enarmor(RopHandle input, RopHandle output, Object type);
    public native int rnp_dearmor(RopHandle input, RopHandle output);
    public native int rnp_key_get_primary_uid(RopHandle key, Vector<?> uid);
    public native int rnp_key_get_uid_count(RopHandle key, Vector<?> count);
    public native int rnp_key_get_uid_at(RopHandle key, int idx, Object uid);
    public native int rnp_key_get_uid_handle_at(RopHandle key, int idx, Vector<?> uid);
    public native int rnp_key_get_signature_count(RopHandle key, Vector<?> count);
    public native int rnp_key_get_signature_at(RopHandle key, int idx, Vector<?> sig);
    public native int rnp_uid_get_signature_count(RopHandle uid, Vector<?> count);
    public native int rnp_uid_get_signature_at(RopHandle uid, int idx, Vector<?> sig);
    public native int rnp_signature_get_alg(RopHandle sig, Vector<?> alg);
    public native int rnp_signature_get_hash_alg(RopHandle sig, Vector<?> alg);
    public native int rnp_signature_get_creation(RopHandle sig, Vector<?> create);
    public native int rnp_signature_get_keyid(RopHandle sig, Vector<?> result);
    public native int rnp_signature_get_signer(RopHandle sig, Vector<?> key);
    public native int rnp_signature_packet_to_json(RopHandle sig, int flags, Vector<?> json);
    public native int rnp_signature_handle_destroy(RopHandle sig);
    public native int rnp_uid_is_revoked(RopHandle uid, Vector<?> result);
    public native int rnp_uid_handle_destroy(Object uid);
    public native int rnp_key_get_subkey_count(RopHandle key, Vector<?> count);
    public native int rnp_key_get_subkey_at(RopHandle key, int idx, Vector<?> subkey);
    public native int rnp_key_get_alg(RopHandle key, Vector<?> alg);
    public native int rnp_key_get_bits(RopHandle key, Vector<?> bits);
    public native int rnp_key_get_dsa_qbits(RopHandle key, Vector<?> qbits);
    public native int rnp_key_get_curve(RopHandle key, Vector<?> curve);
    public native int rnp_key_add_uid(RopHandle key, Object uid, Object hash, long expiration, int key_flags, boolean primary);
    public native int rnp_key_get_fprint(RopHandle key, Vector<?> fprint);
    public native int rnp_key_get_keyid(RopHandle key, Vector<?> keyid);
    public native int rnp_key_get_grip(RopHandle key, Vector<?> grip);
    public native int rnp_key_get_primary_grip(RopHandle key, Vector<?> grip);
    public native int rnp_key_allows_usage(RopHandle key, Object usage, Vector<?> result);
    public native int rnp_key_get_creation(RopHandle key, Vector<?> result);
    public native int rnp_key_get_expiration(RopHandle key, Vector<?> result);
    public native int rnp_key_set_expiration(RopHandle key, long expiry);
    public native int rnp_key_is_revoked(RopHandle key, Vector<?> result);
    public native int rnp_key_get_revocation_reason(RopHandle key, Vector<?> result);
    public native int rnp_key_is_superseded(RopHandle key, Vector<?> result);
    public native int rnp_key_is_compromised(RopHandle key, Vector<?> result);
    public native int rnp_key_is_retired(RopHandle key, Vector<?> result);
    public native int rnp_key_is_locked(RopHandle key, Vector<?> result);
    public native int rnp_key_lock(RopHandle key);
    public native int rnp_key_unlock(RopHandle key, Object password);
    public native int rnp_key_is_protected(RopHandle key, Vector<?> result);
    public native int rnp_key_protect(RopHandle handle, Object password, Object cipher, Object cipher_mode, Object hash, int iterations);
    public native int rnp_key_unprotect(RopHandle key, Object password);
    public native int rnp_key_is_primary(RopHandle key, Vector<?> result);
    public native int rnp_key_is_sub(RopHandle key, Vector<?> result);
    public native int rnp_key_have_secret(RopHandle key, Vector<?> result);
    public native int rnp_key_have_public(RopHandle key, Vector<?> result);
    public native int rnp_key_packets_to_json(RopHandle key, boolean secret, int flags, Vector<?> result);
    public native int rnp_dump_packets_to_json(RopHandle input, int flags, Vector<?> result);
    public native int rnp_dump_packets_to_output(RopHandle input, RopHandle output, int flags);
    public native int rnp_op_sign_create(Vector<?> op, RopHandle ffi, RopHandle input, RopHandle output);
    public native int rnp_op_sign_cleartext_create(Vector<?> op, RopHandle ffi, RopHandle input, RopHandle output);
    public native int rnp_op_sign_detached_create(Vector<?> op, RopHandle ffi, RopHandle input, Object signature);
    public native int rnp_op_sign_add_signature(RopHandle op, RopHandle key, Vector<?> sig);
    public native int rnp_op_sign_signature_set_hash(RopHandle sig, Object hash);
    public native int rnp_op_sign_signature_set_creation_time(RopHandle sig, long create);
    public native int rnp_op_sign_signature_set_expiration_time(RopHandle sig, long expires);
    public native int rnp_op_sign_set_compression(RopHandle op, Object compression, int level);
    public native int rnp_op_sign_set_armor(RopHandle op, boolean armored);
    public native int rnp_op_sign_set_hash(RopHandle op, Object hash);
    public native int rnp_op_sign_set_creation_time(RopHandle op, long create);
    public native int rnp_op_sign_set_expiration_time(RopHandle op, long expire);
    public native int rnp_op_sign_set_file_name(RopHandle op, Object filename);
    public native int rnp_op_sign_set_file_mtime(RopHandle op, long mtime);
    public native int rnp_op_sign_execute(RopHandle op);
    public native int rnp_op_sign_destroy(RopHandle op);
    public native int rnp_op_verify_create(Vector<?> op, RopHandle ffi, RopHandle input, RopHandle output);
    public native int rnp_op_verify_detached_create(Vector<?> op, RopHandle ffi, RopHandle input, RopHandle signature);
    public native int rnp_op_verify_execute(RopHandle op);
    public native int rnp_op_verify_get_signature_count(RopHandle op, Vector<?> count);
    public native int rnp_op_verify_get_signature_at(RopHandle op, int idx, Object sig);
    public native int rnp_op_verify_get_file_info(RopHandle op, Vector<?> filename, Vector<?> mtime);
    public native int rnp_op_verify_get_protection_info(RopHandle op, Vector<?> mode, Vector<?> cipher, Vector<?> valid);
    public native int rnp_op_verify_get_recipient_count(RopHandle op, Vector<?> count);
    public native int rnp_op_verify_get_used_recipient(RopHandle op, Vector<?> recipient);
    public native int rnp_op_verify_get_recipient_at(RopHandle op, int idx, Vector<?> recipient);
    public native int rnp_op_verify_get_symenc_count(RopHandle op, Vector<?> count);
    public native int rnp_op_verify_get_used_symenc(RopHandle op, Vector<?> symenc);
    public native int rnp_op_verify_get_symenc_at(RopHandle op, int idx, Vector<?> symenc);
    public native int rnp_recipient_get_keyid(RopHandle recipient, Vector<?> keyid);
    public native int rnp_recipient_get_alg(RopHandle recipient, Vector<?> alg);
    public native int rnp_symenc_get_cipher(RopHandle symenc, Vector<?> cipher);
    public native int rnp_symenc_get_aead_alg(RopHandle symenc, Vector<?> alg);
    public native int rnp_symenc_get_hash_alg(RopHandle symenc, Vector<?> alg);
    public native int rnp_symenc_get_s2k_type(RopHandle symenc, Vector<?> type);
    public native int rnp_symenc_get_s2k_iterations(RopHandle symenc, Vector<?> iterations);
    public native int rnp_op_verify_destroy(RopHandle op);
    public native int rnp_op_verify_signature_get_status(RopHandle sig);
    public native int rnp_op_verify_signature_get_handle(RopHandle sig,Object handle);
    public native int rnp_op_verify_signature_get_hash(RopHandle sig, Object hash);
    public native int rnp_op_verify_signature_get_key(RopHandle sig, Object key);
    public native int rnp_op_verify_signature_get_times(RopHandle sig, Vector<?> create, Vector<?> expires);
    public native void rnp_buffer_destroy(Object ptr);
    public native void rnp_buffer_clear(RopHandle ptr, long size);
    public native int rnp_input_from_path(Vector<?> input, Object path);
    public native int rnp_input_from_memory(Vector<?> input, Object buf, long buf_len, boolean do_copy);
    public native int rnp_output_to_path(Vector<?> output, Object path);
    public native int rnp_output_to_file(Vector<?> output, Object path, int flags);
    public native int rnp_output_to_memory(Vector<?> output, long max_alloc);
    public native int rnp_output_to_armor(Object base, Vector<?> output, Object type);
    public native int rnp_output_memory_get_buf(Object output, Vector<?> buf, Vector<?> len, boolean do_copy);
    public native int rnp_output_to_null(Object output);
    public native int rnp_output_write(RopHandle output, Object data, long size, Vector<?> written);
    public native int rnp_output_finish(RopHandle output);
    public native int rnp_op_encrypt_create(Vector<?> op, RopHandle ffi, RopHandle input, RopHandle output);
    public native int rnp_op_encrypt_add_recipient(RopHandle op, RopHandle key);
    public native int rnp_op_encrypt_add_signature(RopHandle op, RopHandle key, Object sig);
    public native int rnp_op_encrypt_set_hash(RopHandle op, Object hash);
    public native int rnp_op_encrypt_set_creation_time(RopHandle op, long create);
    public native int rnp_op_encrypt_set_expiration_time(RopHandle op, long expire);
    public native int rnp_op_encrypt_add_password(RopHandle op, Object password, Object s2k_hash, int iterations, Object s2k_cipher);
    public native int rnp_op_encrypt_set_armor(RopHandle op, boolean armored);
    public native int rnp_op_encrypt_set_cipher(RopHandle op, Object cipher);
    public native int rnp_op_encrypt_set_aead(RopHandle op, Object alg);
    public native int rnp_op_encrypt_set_aead_bits(RopHandle op, int bits);
    public native int rnp_op_encrypt_set_compression(RopHandle op, Object compression, int level);
    public native int rnp_op_encrypt_set_file_name(RopHandle op, Object filename);
    public native int rnp_op_encrypt_set_file_mtime(RopHandle op, long mtime);
    public native int rnp_op_encrypt_execute(RopHandle op);
    public native int rnp_op_encrypt_destroy(RopHandle op);
    public native int rnp_decrypt(RopHandle ffi, RopHandle input, RopHandle output);
    public native int rnp_get_public_key_data(RopHandle handle, Vector<?> buf, Vector<?> buf_len);
    public native int rnp_get_secret_key_data(RopHandle handle, Vector<?> buf, Vector<?> buf_len);
    public native int rnp_key_to_json(Object handle, int flags, Vector<?> result);
    public native int rnp_identifier_iterator_create(RopHandle ffi, Object it, Object identifier_type);
    public native int rnp_identifier_iterator_next(RopHandle it, Vector<?> identifier);
    public native int rnp_identifier_iterator_destroy(Object it);
    
    private void ClearCallbacks(RopHandle hnd) {
        RopCB[] cbs =h2cb.get(hnd);
        if(cbs != null) {
            h2cb.remove(hnd);
            for(RopCB cb : cbs)
                if(cb != null)
                    RopLib.native_global_ref(cb, cb.nhnd);
        }
    }
    
    private static void LoadNative(String libName) {
        Path dirPath = null;
        for(String nameForm : new String[] { "lib%s.so", "%s.dll", "lib%s.dylib", "" }) {
            if(nameForm.length() > 0) {
                if(dirPath == null) {
                    String spath = RopLib.class.getResource("RopLib.class").toString();
                    spath = (spath.toLowerCase().indexOf("jar:")==0? spath.substring(4) : spath);
                    try {
                        dirPath = Paths.get(new URI(spath));
                        dirPath = dirPath.toAbsolutePath();
                        for(int count = 0; count < 6; count++) 
                            dirPath = dirPath.getParent();
                    } catch(Exception ex) { dirPath = null; }
                }
                if(dirPath != null) {
                    Path libPath = Paths.get(dirPath.toString(), String.format(nameForm, libName));
                    try { 
                        System.load(libPath.toString()); 
                        break;
                    } catch(Throwable ex) {}
                }
            } else {
                if(dirPath != null) {
                    String libPath = System.getProperty("java.library.path");
                    String spath = dirPath.toString();
                    if(libPath.indexOf(spath) < 0)
                        try { System.setProperty("java.library.path", libPath + ";" + spath);
                        } catch (RuntimeException ex) {}
                }
                System.loadLibrary(libName);
                break;
            }
        }
    }

    private native void nCleanUp();
    private native int nrnp_ffi_destroy(RopHandle ffi);
    private native static RopHandle native_global_ref(Object obj, RopHandle gref);
    private native int nrnp_ffi_set_key_provider(RopHandle ffi, Object gref);
    private native int nrnp_ffi_set_pass_provider(RopHandle ffi, RopHandle gref);
    private native int nrnp_input_from_callback(Vector<?> input, Object cb_ctx);
    private native int nrnp_input_destroy(RopHandle input);
    private native int nrnp_output_to_callback(Vector<?> output, Object acb_ctx);
    private native int nrnp_output_destroy(RopHandle output);

    private TreeMap<RopHandle, RopHandle> retainsI;
    private TreeMap<RopHandle, RopCB[]> h2cb;

    static {
        LoadNative("cjarop");
    }
}


/**
* @version 0.2
* @since   0.2
*/
final class RopCB {
    protected enum Type { PASS, KEY, INPUT, OUTPUT }

    protected Type type;
    protected RopHandle hnd;
    protected RopHandle nhnd;
    protected Object ctx;
    protected Object lstner1;
    
    protected RopCB(Type type, RopHandle hnd, Object ctx, Object lstner1) {
        this.type = type;
        this.hnd = hnd;
        this.nhnd = null;
        this.ctx = ctx;
        this.lstner1 = lstner1;
    }
    
    protected void KeyCB(RopHandle ffi, RopHandle identifier_type, RopHandle identifier, boolean secret) {
        if(ffi.compareTo(hnd) == 0 && lstner1 != null && lstner1 instanceof RopKeyCallBack)
            ((RopKeyCallBack)lstner1).KeyCallBack(hnd, ctx, identifier_type, identifier, secret);
    }

    protected boolean PassCB(RopHandle ffi, RopHandle key, RopHandle pgp_context, RopHandle buf, int buf_len) {
        if(ffi.compareTo(hnd) == 0 && lstner1 != null && lstner1 instanceof RopPassCallBack) {
            RopPassCallBack.Ret cbRet = ((RopPassCallBack)lstner1).PassCallBack(hnd, ctx, key, pgp_context, buf, buf_len);
            if(cbRet.outBuf != null)
                buf.WriteString(cbRet.outBuf, buf_len);
            return cbRet.ret;
        }
        return false;
    }
    
    protected long InReadCB(RopHandle buf, long len) {
        if(lstner1 != null && lstner1 instanceof RopInputCallBack) {
            RopInputCallBack.Ret ret = ((RopInputCallBack)lstner1).InputReadCallBack(ctx, len);
            if(ret.ret && ret.inLen > 0)
                return buf.WriteBytes(ret.inBuf, Math.min(ret.inLen, len));
        }
        return -1;
    }

    protected void InCloseCB() {
        if(lstner1 != null && lstner1 instanceof RopInputCallBack)
            ((RopInputCallBack)lstner1).InputCloseCallBack(ctx);
    }

    protected boolean OutWriteCB(RopHandle buf, long len) {
        if(lstner1 != null && lstner1 instanceof RopOutputCallBack)
            return ((RopOutputCallBack)lstner1).OutputWriteCallBack(ctx, buf, len);
        return false;
    }

    protected void OutCloseCB(boolean discard) {
        if(lstner1 != null && lstner1 instanceof RopOutputCallBack)
            ((RopOutputCallBack)lstner1).OutputCloseCallBack(ctx);
    }
}
