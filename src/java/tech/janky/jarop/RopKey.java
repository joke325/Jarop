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

import java.util.Stack;
import java.time.Instant;
import java.lang.ref.WeakReference;
import java.time.Duration;

import tech.janky.jarop.rop.ROPE;
import tech.janky.jarop.rop.ROPD;
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/** 
* @version 0.3.0
* @since   0.2
*/
public class RopKey extends RopObject {
    protected RopKey(RopBind own, RopHandle kid) throws RopError {
        if(kid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.kid = kid;
        this.outs = new Stack<Object>();
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(kid != null) {
            ret = lib.rnp_key_handle_destroy(kid);
            kid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return kid;
    }

    protected void Detach() {
        kid = null;
    }

    // API

    public String keyid() throws RopError {
        int ret = lib.rnp_key_get_keyid(kid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String alg() throws RopError {
        int ret = lib.rnp_key_get_alg(kid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String primary_grip() throws RopError {
        int ret = lib.rnp_key_get_primary_grip(kid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String fprint() throws RopError {
        int ret = lib.rnp_key_get_fprint(kid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String grip() throws RopError {
        int ret = lib.rnp_key_get_grip(kid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String primary_uid() throws RopError {
        int ret = lib.rnp_key_get_primary_uid(kid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String curve() throws RopError {
        int ret = lib.rnp_key_get_curve(kid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String revocation_reason() throws RopError {
        int ret = lib.rnp_key_get_revocation_reason(kid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public void set_expiration(Duration expiry) throws RopError {
        int ret = lib.rnp_key_set_expiration(kid, Util.TimeDelta2Sec(expiry));
        Util.Return(ret);
    }
    public boolean is_revoked() throws RopError {
        int ret = lib.rnp_key_is_revoked(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean is_superseded() throws RopError {
        int ret = lib.rnp_key_is_superseded(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean is_compromised() throws RopError {
        int ret = lib.rnp_key_is_compromised(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean is_retired() throws RopError {
        int ret = lib.rnp_key_is_retired(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean is_locked() throws RopError {
        int ret = lib.rnp_key_is_locked(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean is_protected() throws RopError {
        int ret = lib.rnp_key_is_protected(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean is_primary() throws RopError {
        int ret = lib.rnp_key_is_primary(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean is_sub() throws RopError {
        int ret = lib.rnp_key_is_sub(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean have_secret() throws RopError {
        int ret = lib.rnp_key_have_secret(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean have_public() throws RopError {
        int ret = lib.rnp_key_have_public(kid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public Instant creation() throws RopError {
        int ret = lib.rnp_key_get_creation(kid, outs);
        return Instant.ofEpochSecond(Util.PopLong(lib, outs, ret, true));
    }
    public Duration expiration() throws RopError {
        int ret = lib.rnp_key_get_expiration(kid, outs);
        return Duration.ofSeconds(Util.PopLong(lib, outs, ret, true));
    }
    public int uid_count() throws RopError {
        int ret = lib.rnp_key_get_uid_count(kid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public int signature_count() throws RopError {
        int ret = lib.rnp_key_get_signature_count(kid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public int bits() throws RopError {
        int ret = lib.rnp_key_get_bits(kid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public int dsa_qbits() throws RopError {
        int ret = lib.rnp_key_get_dsa_qbits(kid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public int subkey_count() throws RopError {
        int ret = lib.rnp_key_get_subkey_count(kid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public String get_uid_at(int idx) throws RopError {
        int ret = lib.rnp_key_get_uid_at(kid, idx, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public RopData to_json(boolean publicMpis, boolean secretMpis, boolean signatures, boolean signMpis) throws RopError {
        int flags = (publicMpis? ROPD.RNP_JSON_PUBLIC_MPIS : 0);
        flags |= (secretMpis? ROPD.RNP_JSON_SECRET_MPIS : 0);
        flags |= (signatures? ROPD.RNP_JSON_SIGNATURES : 0);
        flags |= (signMpis? ROPD.RNP_JSON_SIGNATURE_MPIS : 0);
        int ret = lib.rnp_key_to_json(kid, flags, outs);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), 0);
        own.get().PutObj(data, 0);
        return data;
    }
    public RopData to_json() throws RopError {
        return to_json(true, true, true, true);
    }
    public RopData packets_to_json(boolean secret, boolean mpi, boolean raw, boolean grip) throws RopError {
        int flags = (mpi? ROPD.RNP_JSON_DUMP_MPI : 0);
        flags |= (raw? ROPD.RNP_JSON_DUMP_RAW : 0);
        flags |= (grip? ROPD.RNP_JSON_DUMP_GRIP : 0);
        int ret = lib.rnp_key_packets_to_json(kid, secret, flags, outs);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), 0);
        own.get().PutObj(data, 0);
        return data;
    }
    public RopData packets_to_json(boolean secret) throws RopError {
        return packets_to_json(secret, true, true, true);
    }
    public boolean allows_usage(String usage) throws RopError {
        int ret = lib.rnp_key_allows_usage(kid, usage, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean allows_usages(String[] usages) throws RopError {
        for(String usage : usages)
            if(!allows_usage(usage))
                return false;
        return true;
    }
    public boolean disallows_usages(String[] usages) throws RopError {
        for(String usage : usages)
            if(allows_usage(usage))
                return false;
        return true;
    }
    public void lock() throws RopError {
        int ret = lib.rnp_key_lock(kid);
        Util.Return(ret);
    }
    public void unlock(String password) throws RopError {
        int ret = lib.rnp_key_unlock(kid, password);
        Util.Return(ret);
    }

    public RopUidHandle get_uid_handle_at(int idx, int tag) throws RopError {
        int ret = lib.rnp_key_get_uid_handle_at(kid, idx, outs);
        RopUidHandle uid = new RopUidHandle(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(uid, tag);
        return uid;
    }
    public RopUidHandle get_uid_handle_at(int idx) throws RopError {
        return get_uid_handle_at(idx, 0);
    }
    public void protect(String password, String cipher, String cipherMode, String hash, int iterations) throws RopError {
        int ret = lib.rnp_key_protect(kid, password, cipher, cipherMode, hash, iterations);
        Util.Return(ret);
    }
    public void unprotect(String password) throws RopError {
        int ret = lib.rnp_key_unprotect(kid, password);
        Util.Return(ret);
    }
    public RopData public_key_data() throws RopError {
        int ret = lib.rnp_get_public_key_data(kid, outs, outs);
        long len = Util.PopLong(lib, outs, ret, false);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), len);
        own.get().PutObj(data, 0);
        return data;
    }
    public RopData secret_key_data() throws RopError {
        int ret = lib.rnp_get_secret_key_data(kid, outs, outs);
        long len = Util.PopLong(lib, outs, ret, false);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), len);
        own.get().PutObj(data, 0);
        return data;
    }
    public void add_uid(String uid, String hash, Instant expiration, int keyFlags, boolean primary) throws RopError {
        int ret = lib.rnp_key_add_uid(kid, uid, hash, Util.Datetime2TS(expiration), keyFlags, primary);
        Util.Return(ret);
    }
    public RopKey get_subkey_at(int idx, int tag) throws RopError {
        int ret = lib.rnp_key_get_subkey_at(kid, idx, outs);
        RopKey key = new RopKey(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(key, tag);
        return key;
    }
    public RopKey get_subkey_at(int idx) throws RopError {
        return get_subkey_at(idx, 0);
    }
    public RopSign get_signature_at(int idx, int tag) throws RopError {
        int ret = lib.rnp_key_get_signature_at(kid, idx, outs);
        RopSign sign = new RopSign(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(sign, tag);
        return sign;
    }
    public RopSign get_signature_at(int idx) throws RopError {
        return get_signature_at(idx, 0);
    }
    public void export(RopOutput output, boolean pub, boolean sec, boolean subkey, boolean armored) throws RopError {
        RopHandle outp = (output!=null? output.getHandle() : null);
        int flags = (pub? ROPD.RNP_KEY_EXPORT_PUBLIC : 0);
        flags |= (sec? ROPD.RNP_KEY_EXPORT_SECRET : 0);
        flags |= (subkey? ROPD.RNP_KEY_EXPORT_SUBKEYS : 0);
        flags |= (armored? ROPD.RNP_KEY_EXPORT_ARMORED : 0);
        int ret = lib.rnp_key_export(kid, outp, flags);
        Util.Return(ret);
    }
    public void export_public(RopOutput output, boolean subkey, boolean armored) throws RopError {
        export(output, true, false, subkey, armored);
    }
    public void export_public(RopOutput output, boolean subkey) throws RopError {
        export(output, true, false, subkey, false);
    }
    public void export_public(RopOutput output) throws RopError {
        export(output, true, false, false, false);
    }
    public void export_secret(RopOutput output, boolean subkey, boolean armored) throws RopError {
        export(output, false, true, subkey, armored);
    }
    public void export_secret(RopOutput output, boolean subkey) throws RopError {
        export(output, false, true, subkey, false);
    }
    public void export_secret(RopOutput output) throws RopError {
        export(output, false, true, false, false);
    }
    public void remove(boolean pub, boolean sec, boolean subkeys) throws RopError {
        int flags = (pub? ROPD.RNP_KEY_REMOVE_PUBLIC : 0);
        flags |= (sec? ROPD.RNP_KEY_REMOVE_SECRET : 0);
        flags |= (subkeys? ROPD.RNP_KEY_REMOVE_SUBKEYS : 0);
        int ret = lib.rnp_key_remove(kid, flags);
        Util.Return(ret);
    }
    public void remove(boolean pub, boolean sec) throws RopError {
        remove(pub, sec, false);
    }
    public void remove_public(boolean subkeys) throws RopError {
        remove(true, false, subkeys);
    }
    public void remove_public() throws RopError {
        remove(true, false, false);
    }
    public void remove_secret(boolean subkeys) throws RopError {
        remove(false, true, subkeys);
    }
    public void remove_secret() throws RopError {
        remove(false, true, false);
    }
    public void export_revocation(RopOutput output, String hash, String code, String reason) throws RopError {
        RopHandle outp = (output!=null? output.getHandle() : null);
        int ret = lib.rnp_key_export_revocation(kid, outp, 0, hash, code, reason);
        Util.Return(ret);
    }
    public void revoke(String hash, String code, String reason) throws RopError {
        int ret = lib.rnp_key_revoke(kid, 0, hash, code, reason);
        Util.Return(ret);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle kid;
    private Stack<Object> outs;
}
