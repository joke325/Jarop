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

import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/**
* @version 0.2
* @since   0.2
*/
public class RopVeriSignature {
    public RopVeriSignature(RopBind own, RopHandle sgid) throws RopError {
        if(sgid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.sgid = sgid;
        this.outs = new Stack<Object>();
    }

    public RopHandle getHandle() {
        return sgid;
    }

    // API

    public String hash() throws RopError {
        int ret = lib.rnp_op_verify_signature_get_hash(sgid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public int status() {
        return lib.rnp_op_verify_signature_get_status(sgid);
    }
    public RopSign get_handle(int tag) throws RopError {
        int ret = lib.rnp_op_verify_signature_get_handle(sgid, outs);
        RopSign sign = new RopSign(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(sign, tag);
        return sign;
    }
    public RopSign get_handle() throws RopError {
        return get_handle(0);
    }
    public RopKey get_key(int tag) throws RopError {
        int ret = lib.rnp_op_verify_signature_get_key(sgid, outs);
        RopKey key = new RopKey(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(key, tag);
        return key;
    }
    public RopKey get_key() throws RopError {
        return get_key(0);
    }
    public Instant[] get_times() throws RopError {
        int ret = lib.rnp_op_verify_signature_get_times(sgid, outs, outs);
        Instant exp = Instant.ofEpochSecond(Util.PopLong(lib, outs, ret, false));
        Instant cre = Instant.ofEpochSecond(Util.PopLong(lib, outs, ret, true));
        return new Instant[] { cre, exp };
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle sgid;
    private Stack<Object> outs;
}
