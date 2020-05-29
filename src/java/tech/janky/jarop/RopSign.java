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
import java.util.Stack;

import tech.janky.jarop.rop.ROPE;
import tech.janky.jarop.rop.ROPD;
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/**
* @version 0.2
* @since   0.2
*/
public class RopSign extends RopObject {
    protected RopSign(RopBind own, RopHandle sgid) throws RopError {
        if(sgid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.sgid = sgid;
        this.outs = new Stack<Object>();
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(sgid != null) {
            ret = lib.rnp_signature_handle_destroy(sgid);
            sgid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return sgid;
    }

    // API

    public String alg() throws RopError {
        int ret = lib.rnp_signature_get_alg(sgid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String hash_alg() throws RopError {
        int ret = lib.rnp_signature_get_hash_alg(sgid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public Instant creation() throws RopError {
        int ret = lib.rnp_signature_get_creation(sgid, outs);
        return Instant.ofEpochSecond(Util.PopLong(lib, outs, ret, true));
    }
    public String keyid() throws RopError {
        int ret = lib.rnp_signature_get_keyid(sgid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public RopKey get_signer(int tag) throws RopError {
        int ret = lib.rnp_signature_get_signer(sgid, outs);
        RopKey key = new RopKey(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(key, tag);
        return key;
    }
    public RopKey get_signer() throws RopError {
        return get_signer(0);
    }
    public RopData to_json(boolean mpi, boolean raw, boolean grip) throws RopError {
        int flags = (mpi? ROPD.RNP_JSON_DUMP_MPI : 0);
        flags |= (raw? ROPD.RNP_JSON_DUMP_RAW : 0);
        flags |= (grip? ROPD.RNP_JSON_DUMP_GRIP : 0);
        int ret = lib.rnp_signature_packet_to_json(sgid, flags, outs);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), 0);
        own.get().PutObj(data, 0);
        return data;
    }
    public RopData to_json() throws RopError {
        return to_json(false, false, false);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle sgid;
    private Stack<Object> outs;
}
