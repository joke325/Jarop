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

import tech.janky.jarop.rop.ROPE;
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/**
* @version 0.14.0
* @since   0.2
*/
public class RopUidHandle extends RopObject {
    protected RopUidHandle(RopBind own, RopHandle huid) {
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.huid = huid;
        this.outs = new Stack<Object>();
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(huid != null) {
            ret = lib.rnp_uid_handle_destroy(huid);
            huid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return huid;
    }
    
    // API
    
    public int get_type() throws RopError {
        int ret = lib.rnp_uid_get_type(huid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public RopData get_data() throws RopError {
        int ret = lib.rnp_uid_get_data(huid, outs, outs);
        long len = Util.PopLong(lib, outs, ret, false);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), len);
        own.get().PutObj(data, 0);
        return data;
    }
    public boolean is_primary() throws RopError {
        int ret = lib.rnp_uid_is_primary(huid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public boolean is_valid() throws RopError {
        int ret = lib.rnp_uid_is_valid(huid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public int signature_count() throws RopError {
        int ret = lib.rnp_uid_get_signature_count(huid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public boolean is_revoked() throws RopError {
        int ret = lib.rnp_uid_is_revoked(huid, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public RopSign get_signature_at(int idx, int tag) throws RopError {
        int ret = lib.rnp_uid_get_signature_at(huid, idx, outs);
        RopSign sign = new RopSign(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(sign, tag);
        return sign;
    }
    public RopSign get_signature_at(int idx) throws RopError {
        return get_signature_at(idx, 0);
    }
    public RopSign get_revocation_signature(int tag) throws RopError {
        int ret = lib.rnp_uid_get_revocation_signature(huid, outs);
        RopSign sign = new RopSign(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(sign, tag);
        return sign;
    }
    public RopSign get_revocation_signature() throws RopError {
        return get_revocation_signature(0);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle huid;
    private Stack<Object> outs;
}
