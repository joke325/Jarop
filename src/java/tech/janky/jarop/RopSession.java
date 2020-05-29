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

package tech.janky.jarop;

import java.lang.ref.WeakReference;
import java.util.Stack;

import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;
import tech.janky.jarop.rop.ROPE;
import tech.janky.jarop.rop.ROPD;
import tech.janky.jarop.rop.RopPassCallBack;
import tech.janky.jarop.rop.RopKeyCallBack;


/**
* Wraps FFI related ops
* @version 0.2
* @since   0.2
*/
public class RopSession extends RopObject implements RopPassCallBack, RopKeyCallBack {
    protected RopSession(RopBind own, RopHandle sid) throws RopError {
        if(sid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.sid = sid;
        this.passProvider = null;
        this.keyProvider = null;
        this.outs = new Stack<Object>();
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(sid != null) {
            ret = lib.rnp_ffi_destroy(sid);
            sid = null;
        }
        return ret;
    }

    public RopHandle getHandle() {
        return sid;
    }

    protected void Detach() {
        sid = null;
    }

    public WeakReference<RopBind> getBind() {
        return own;
    }

    // API

    public int public_key_count() throws RopError {
        int ret = lib.rnp_get_public_key_count(sid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public int secret_key_count() throws RopError {
        int ret = lib.rnp_get_secret_key_count(sid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }

    public RopOpSign op_sign_create(RopInput input, RopOutput output, boolean cleartext, boolean detached, int tag) throws RopError {
        int ret = ROPE.RNP_SUCCESS;
        RopHandle inp = (input!=null? input.getHandle() : null);
        RopHandle outp = (output!=null? output.getHandle() : null);
        if(cleartext)
            ret = lib.rnp_op_sign_cleartext_create(outs, sid, inp, outp);
        else if(detached)
            ret = lib.rnp_op_sign_detached_create(outs, sid, inp, outp);
        else
            ret = lib.rnp_op_sign_create(outs, sid, inp, outp);
        RopOpSign sign = new RopOpSign(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(sign, tag);
        return sign;
    }
    public RopOpSign op_sign_create(RopInput input, RopOutput output, boolean cleartext, boolean detached) throws RopError {
        return op_sign_create(input, output, cleartext, detached, 0);
    }    	
    public RopOpSign op_sign_create(RopInput input, RopOutput output) throws RopError {
        return op_sign_create(input, output, false, false, 0);
    }
    public RopOpSign op_sign_create_cleartext(RopInput input, RopOutput output) throws RopError {
        return op_sign_create(input, output, true, false, 0);
    }
    public RopOpSign op_sign_create_detached(RopInput input, RopOutput output) throws RopError {
        return op_sign_create(input, output, false, true, 0);
    }
    public RopOpGenerate op_generate_create(String keyAlg, RopKey primary, int tag) throws RopError {
        int ret;
        if(primary == null)
            ret = lib.rnp_op_generate_create(outs, sid, keyAlg);
        else
            ret = lib.rnp_op_generate_subkey_create(outs, sid, primary!=null? primary.getHandle() : null, keyAlg);
        RopOpGenerate opg = new RopOpGenerate(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(opg, tag);
        return opg;
    }
    public RopOpGenerate op_generate_create_subkey(String keyAlg, RopKey primary) throws RopError {
        return op_generate_create(keyAlg, primary, 0);
    }
    public RopOpGenerate op_generate_create(String keyAlg) throws RopError {
        return op_generate_create(keyAlg, null, 0);
    }
    public RopOpEncrypt op_encrypt_create(RopInput input, RopOutput output, int tag) throws RopError {
        RopHandle inp = (input!=null? input.getHandle() : null);
        RopHandle outp = (output!=null? output.getHandle() : null);
        int ret = lib.rnp_op_encrypt_create(outs, sid, inp, outp);
        RopOpEncrypt ope = new RopOpEncrypt(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(ope, tag);
        return ope;
    }
    public RopOpEncrypt op_encrypt_create(RopInput input, RopOutput output) throws RopError {
        return op_encrypt_create(input, output, 0);
    }
    public RopOpVerify op_verify_create(RopInput input, RopOutput output, RopInput signature, int tag) throws RopError {
        RopHandle inp = (input!=null? input.getHandle() : null);
        int ret;
        if(signature == null) {
            RopHandle outp = (output!=null? output.getHandle() : null);
            ret = lib.rnp_op_verify_create(outs, sid, inp, outp);
        } else {
            RopHandle sig = (signature!=null? signature.getHandle() : null);
            ret = lib.rnp_op_verify_detached_create(outs, sid, inp, sig);
        }
        RopOpVerify opv = new RopOpVerify(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(opv, tag);
        return opv;
    }
    public RopOpVerify op_verify_create(RopInput input, RopOutput output, RopInput signature) throws RopError {
        return op_verify_create(input, output, signature, 0);
    }    
    public RopOpVerify op_verify_create(RopInput input, RopOutput output) throws RopError {
        return op_verify_create(input, output, null, 0);
    }
    public RopOpVerify op_verify_create(RopInput input, RopInput signature) throws RopError {
        return op_verify_create(input, null, signature, 0);
    }
    public void load_keys(String format, RopInput input, boolean pub, boolean sec) throws RopError {
        RopHandle inp = (input!=null? input.getHandle() : null);
        int flags = (pub? ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS : 0);
        flags |= (sec? ROPD.RNP_LOAD_SAVE_SECRET_KEYS : 0);
        int ret = lib.rnp_load_keys(sid, format, inp, flags);
        Util.Return(ret);
    }
    public void load_keys_public(String format, RopInput input) throws RopError {
        load_keys(format, input, true, false);
    }
    public void load_keys_secret(String format, RopInput input) throws RopError {
        load_keys(format, input, false, true);
    }    
    public void unload_keys(boolean pub, boolean sec) throws RopError {
        int flags = (pub? ROPD.RNP_KEY_UNLOAD_PUBLIC : 0);
        flags |= (sec? ROPD.RNP_KEY_UNLOAD_SECRET : 0);
        int ret = lib.rnp_unload_keys(sid, flags);
        Util.Return(ret);
    }
    public void unload_keys_public() throws RopError {
        unload_keys(true, false);
    }    
    public void unload_keys_secret() throws RopError {
        unload_keys(false, true);
    }    
    private RopKey PutKey(RopHandle keyHnd, int tag) throws RopError {
        RopKey key = new RopKey(own.get(), keyHnd);
        own.get().PutObj(key, tag);
        return key;
    }
    public RopKey locate_key(String identifier_type, String identifier, int tag) throws RopError {
        int ret = lib.rnp_locate_key(sid, identifier_type, identifier, outs);
        return PutKey(Util.PopHandle(lib, outs, ret, true), tag);
    }
    public RopKey locate_key(String identifier_type, String identifier) throws RopError {
        return locate_key(identifier_type, identifier, 0);
    }
    public RopKey generate_key_rsa(int bits, int subbits, String userid, String password, int tag) throws RopError {
        int ret = lib.rnp_generate_key_rsa(sid, bits, subbits, userid, password, outs);
        return PutKey(Util.PopHandle(lib, outs, ret, true), tag);
    }
    public RopKey generate_key_rsa(int bits, int subbits, String userid, String password) throws RopError {
        return generate_key_rsa(bits, subbits, userid, password, 0);
    }
    public RopKey generate_key_dsa_eg(int bits, int subbits, String userid, String password, int tag) throws RopError {
        int ret = lib.rnp_generate_key_dsa_eg(sid, bits, subbits, userid, password, outs);
        return PutKey(Util.PopHandle(lib, outs, ret, true), tag);
    }
    public RopKey generate_key_dsa_eg(int bits, int subbits, String userid, String password) throws RopError {
        return generate_key_dsa_eg(bits, subbits, userid, password, 0);
    }
    public RopKey generate_key_ec(String curve, String userid, String password, int tag) throws RopError {
        int ret = lib.rnp_generate_key_ec(sid, curve, userid, password, outs);
        return PutKey(Util.PopHandle(lib, outs, ret, true), tag);
    }
    public RopKey generate_key_ec(String curve, String userid, String password) throws RopError {
        return generate_key_ec(curve, userid, password, 0);
    }	
    public RopKey generate_key_25519(String userid, String password, int tag) throws RopError {
        int ret = lib.rnp_generate_key_25519(sid, userid, password, outs);
        return PutKey(Util.PopHandle(lib, outs, ret, true), tag);
    }
    public RopKey generate_key_25519(String userid, String password) throws RopError {
        return generate_key_25519(userid, password, 0);
    }
    public RopKey generate_key_sm2(String userid, String password, int tag) throws RopError {
        int ret = lib.rnp_generate_key_sm2(sid, userid, password, outs);
        return PutKey(Util.PopHandle(lib, outs, ret, true), tag);
    }
    public RopKey generate_key_sm2(String userid, String password) throws RopError {
        return generate_key_sm2(userid, password, 0);
    }
    public RopKey generate_key_ex(String keyAlg, String subAlg, int keyBits, int subBits, String keyCurve, String subCurve, String userid, String password, int tag) throws RopError {
        int ret = lib.rnp_generate_key_ex(sid, keyAlg, subAlg, keyBits, subBits, keyCurve, subCurve, userid, password, outs);
        return PutKey(Util.PopHandle(lib, outs, ret, true), tag);
    }
    public RopKey generate_key_ex(String keyAlg, String subAlg, int keyBits, int subBits, String keyCurve, String subCurve, String userid, String password) throws RopError {
        return generate_key_ex(keyAlg, subAlg, keyBits, subBits, keyCurve, subCurve, userid, password, 0);
    }	
    public RopData import_keys(RopInput input, boolean pub, boolean sec) throws RopError {
        RopHandle inp = (input!=null? input.getHandle() : null);
        int flags = (pub? ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS : 0);
        flags |= (sec? ROPD.RNP_LOAD_SAVE_SECRET_KEYS : 0);
        int ret = lib.rnp_import_keys(sid, inp, flags, outs);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), 0);
        own.get().PutObj(data, 0);
        return data;
    }
    public RopData import_keys_public(RopInput input) throws RopError {
        return import_keys(input, true, false);
    }
    public RopData import_keys_secret(RopInput input) throws RopError {
        return import_keys(input, false, true);
    }
    public RopData import_keys(RopInput input) throws RopError {
        return import_keys(input, false, false);
    }

    public void set_pass_provider(SessionPassCallBack getpasscb, Object getpasscbCtx) throws RopError {
        passProvider = getpasscb;
        int ret = lib.rnp_ffi_set_pass_provider(sid, this, getpasscbCtx);
        Util.Return(ret);
    }
    public RopIdIterator identifier_iterator_create(String identifier_type, int tag) throws RopError {
        int ret = lib.rnp_identifier_iterator_create(sid, outs, identifier_type);
        RopIdIterator iter = new RopIdIterator(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(iter, tag);
        return iter;
    }
    public RopIdIterator identifier_iterator_create(String identifier_type) throws RopError {
        return identifier_iterator_create(identifier_type, 0);
    }
    public void set_log_fd(int fd) throws RopError {
        int ret = lib.rnp_ffi_set_log_fd(sid, fd);
        Util.Return(ret);
    }

    public void set_key_provider(SessionKeyCallBack getkeycb, Object getkeycbCtx) throws RopError {
        keyProvider = getkeycb;
        int ret = lib.rnp_ffi_set_key_provider(sid, this, getkeycbCtx);
        Util.Return(ret);
    }
    public void save_keys(String format, RopOutput output, boolean pub, boolean sec) throws RopError {
        RopHandle outp = (output!=null? output.getHandle() : null);
        int flags = (pub? ROPD.RNP_LOAD_SAVE_PUBLIC_KEYS : 0);
        flags |= (sec? ROPD.RNP_LOAD_SAVE_SECRET_KEYS : 0);
        int ret = lib.rnp_save_keys(sid, format, outp, flags);
        Util.Return(ret);
    }
    public void save_keys_public(String format, RopOutput output) throws RopError {
        save_keys(format, output, true, false);
    }
    public void save_keys_secret(String format, RopOutput output) throws RopError {
        save_keys(format, output, false, true);
    }
    public RopData generate_key_json(RopData json) throws RopError {
        int ret = lib.rnp_generate_key_json(sid, json.getDataObj(), outs);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), 0);
        own.get().PutObj(data, 0);
        return data;
    }
    public void decrypt(RopInput input, RopOutput output) throws RopError {
        RopHandle inp = (input!=null? input.getHandle() : null);
        RopHandle outp = (output!=null? output.getHandle() : null);
        int ret = lib.rnp_decrypt(sid, inp, outp);
        Util.Return(ret);
    }
    
    // Implements RopPassCallBack
    public RopPassCallBack.Ret PassCallBack(RopHandle ffi, Object ctx, RopHandle key, RopHandle pgpCtx, RopHandle buf, int bufLen) {
        if(passProvider != null) {
            // create new Session and Key handlers
            try {
                RopSession ropSes = (!ffi.isNull()? new RopSession(own.get(), ffi) : null);
                RopKey ropKey = (!key.isNull()? new RopKey(own.get(), key) : null);
                SessionPassCallBack.Ret scbRet = passProvider.PassCallBack(ropSes, ctx, ropKey, RopHandle.Str(pgpCtx), bufLen);
                if(ropSes != null)
                    ropSes.Detach();
                if(ropKey != null)
                    ropKey.Detach();
                return new RopPassCallBack.Ret(scbRet.ret, scbRet.outBuf);
            } catch(RopError ex) {}
        }
        return new RopPassCallBack.Ret(false, null);
    }

    // Implements RopKeyCallBack
    public void KeyCallBack(RopHandle ffi, Object ctx, RopHandle identifierType, RopHandle identifier, boolean secret) {
        if(keyProvider != null) {
            // create a new Session handler
            try {
                RopSession ropSes = (!ffi.isNull()? new RopSession(own.get(), ffi) : null);
                keyProvider.KeyCallBack(ropSes, ctx, RopHandle.Str(identifierType), RopHandle.Str(identifier), secret);
                if(ropSes != null)
                    ropSes.Detach();
            } catch(RopError ex) {}
        }
    }
    
    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle sid;
    private SessionPassCallBack passProvider;
    private SessionKeyCallBack keyProvider;
    private Stack<Object> outs;
}
