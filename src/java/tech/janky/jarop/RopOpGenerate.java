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
import java.time.Instant;
import java.time.Duration;
import java.util.Stack;

import tech.janky.jarop.rop.ROPE;
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/** 
* @version 0.2
* @since   0.2
*/
public class RopOpGenerate extends RopObject {
    protected RopOpGenerate(RopBind own, RopHandle opid) throws RopError {
        if(opid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.opid = opid;
        this.outs = new Stack<Object>();
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(opid != null) {
            ret = lib.rnp_op_generate_destroy(opid);
            opid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return opid;
    }

    // API

    public void set_bits(int bits) throws RopError {
        int ret = lib.rnp_op_generate_set_bits(opid, bits);
        Util.Return(ret);
    }
    public void set_hash(String hash) throws RopError {
        int ret = lib.rnp_op_generate_set_hash(opid, hash);
        Util.Return(ret);
    }
    public void set_dsa_qbits(int qbits) throws RopError {
        int ret = lib.rnp_op_generate_set_dsa_qbits(opid, qbits);
        Util.Return(ret);
    }
    public void set_curve(String curve) throws RopError {
        int ret = lib.rnp_op_generate_set_curve(opid, curve);
        Util.Return(ret);
    }
    public void set_protection_password(String password) throws RopError {
        int ret = lib.rnp_op_generate_set_protection_password(opid, password);
        Util.Return(ret);
    }
    public void set_request_password(boolean request) throws RopError {
        int ret = lib.rnp_op_generate_set_request_password(opid, request);
        Util.Return(ret);
    }
    public void set_protection_cipher(String cipher) throws RopError {
        int ret = lib.rnp_op_generate_set_protection_cipher(opid, cipher);
        Util.Return(ret);
    }
    public void set_protection_hash(String hash) throws RopError {
        int ret = lib.rnp_op_generate_set_protection_hash(opid, hash);
        Util.Return(ret);
    }
    public void set_protection_mode(String mode) throws RopError {
        int ret = lib.rnp_op_generate_set_protection_mode(opid, mode);
        Util.Return(ret);
    }
    public void set_protection_iterations(int iterations) throws RopError {
        int ret = lib.rnp_op_generate_set_protection_iterations(opid, iterations);
        Util.Return(ret);
    }
    public void add_usage(String usage) throws RopError {
        int ret = lib.rnp_op_generate_add_usage(opid, usage);
        Util.Return(ret);
    }
    public void clear_usage() throws RopError {
        int ret = lib.rnp_op_generate_clear_usage(opid);
        Util.Return(ret);
    }
    public void set_usages(String[] usages) throws RopError {
        clear_usage();
        for(String usage : usages)
            add_usage(usage);
    }
    public void set_userid(String userid) throws RopError {
        int ret = lib.rnp_op_generate_set_userid(opid, userid);
        Util.Return(ret);
    }
    public void set_expiration(Duration expiration) throws RopError {
        int ret = lib.rnp_op_generate_set_expiration(opid, Util.TimeDelta2Sec(expiration));
        Util.Return(ret);
    }
    public void add_pref_hash(String hash) throws RopError {
        int ret = lib.rnp_op_generate_add_pref_hash(opid, hash);
        Util.Return(ret);
    }
    public void clear_pref_hashes() throws RopError {
        int ret = lib.rnp_op_generate_clear_pref_hashes(opid);
        Util.Return(ret);
    }
    public void set_pref_hashes(String[] hashes) throws RopError {
        clear_pref_hashes();
        for(String hash : hashes)
            add_pref_hash(hash);
    }
    public void add_pref_compression(String compression) throws RopError {
        int ret = lib.rnp_op_generate_add_pref_compression(opid, compression);
        Util.Return(ret);
    }
    public void clear_pref_compression() throws RopError {
        int ret = lib.rnp_op_generate_clear_pref_compression(opid);
        Util.Return(ret);
    }
    public void set_pref_compressions(String[] compressions) throws RopError {
        clear_pref_compression();
        for(String compression : compressions)
            add_pref_compression(compression);
    }
    public void add_pref_cipher(String cipher) throws RopError {
        int ret = lib.rnp_op_generate_add_pref_cipher(opid, cipher);
        Util.Return(ret);
    }
    public void clear_pref_ciphers() throws RopError {
        int ret = lib.rnp_op_generate_clear_pref_ciphers(opid);
        Util.Return(ret);
    }
    public void set_pref_ciphers(String[] ciphers) throws RopError {
        clear_pref_ciphers();
        for(String cipher : ciphers)
            add_pref_cipher(cipher);
    }
    public void set_pref_keyserver(String keyserver) throws RopError {
        int ret = lib.rnp_op_generate_set_pref_keyserver(opid, keyserver);
        Util.Return(ret);
    }
    public void execute() throws RopError {
        int ret = lib.rnp_op_generate_execute(opid);
        Util.Return(ret);
    }
    public RopKey get_key(int tag) throws RopError {
        int ret = lib.rnp_op_generate_get_key(opid, outs);
        RopKey uid = new RopKey(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(uid, tag);
        return uid;
    }
    public RopKey get_key() throws RopError {
        return get_key(0);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle opid;
    private Stack<Object> outs;
}
