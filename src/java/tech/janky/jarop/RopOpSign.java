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
import java.time.Instant;
import java.time.Duration;

import tech.janky.jarop.rop.ROPE;
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/** 
* @version 0.2
* @since   0.2
*/
public class RopOpSign extends RopObject {
    protected RopOpSign(RopBind own, RopHandle opid) throws RopError {
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
            ret = lib.rnp_op_sign_destroy(opid);
            opid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return opid;
    }

    // API

    public void set_compression(String compression, int level) throws RopError {
        int ret = lib.rnp_op_sign_set_compression(opid, compression, level);
        Util.Return(ret);
    }
    public void set_armor(boolean armored) throws RopError {
        int ret = lib.rnp_op_sign_set_armor(opid, armored);
        Util.Return(ret);
    }
    public void set_hash(String hash) throws RopError {
        int ret = lib.rnp_op_sign_set_hash(opid, hash);
        Util.Return(ret);
    }
    public void set_creation_time(Instant create) throws RopError {
        int ret = lib.rnp_op_sign_set_creation_time(opid, Util.Datetime2TS(create));
        Util.Return(ret);
    }
    public void set_expiration_time(Instant expire) throws RopError {
        int ret = lib.rnp_op_sign_set_expiration_time(opid, Util.Datetime2TS(expire));
        Util.Return(ret);
    }
    public void set_expiration(Duration expire) throws RopError {
        int ret = lib.rnp_op_sign_set_expiration_time(opid, Util.TimeDelta2Sec(expire));
        Util.Return(ret);
    }
    public void set_file_name(String filename) throws RopError {
        int ret = lib.rnp_op_sign_set_file_name(opid, filename);
        Util.Return(ret);
    }
    public void set_file_mtime(Instant mtime) throws RopError {
        int ret = lib.rnp_op_sign_set_file_mtime(opid, Util.Datetime2TS(mtime));
        Util.Return(ret);
    }
    public void execute() throws RopError {
        int ret = lib.rnp_op_sign_execute(opid);
        Util.Return(ret);
    }
    public RopSignSignature add_signature(RopKey key) throws RopError {
        int ret = lib.rnp_op_sign_add_signature(opid, key!=null? key.getHandle() : null, outs);
        return new RopSignSignature(own.get(), Util.PopHandle(lib, outs, ret, true));
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle opid;
    private Stack<Object> outs;
}
