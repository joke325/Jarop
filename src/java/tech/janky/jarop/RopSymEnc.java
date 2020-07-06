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
* @version 0.3.0
* @since   0.3.0
*/
public class RopSymEnc extends RopObject {
    protected RopSymEnc(RopBind own, RopHandle seid) throws RopError {
        if(seid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.seid = seid;
        this.outs = new Stack<Object>();
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(seid != null) {
            seid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return seid;
    }

    // API

    public String get_cipher() throws RopError {
        int ret = lib.rnp_symenc_get_cipher(seid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String get_aead_alg() throws RopError {
        int ret = lib.rnp_symenc_get_aead_alg(seid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String get_hash_alg() throws RopError {
        int ret = lib.rnp_symenc_get_hash_alg(seid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String get_s2k_type() throws RopError {
        int ret = lib.rnp_symenc_get_s2k_type(seid, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public int get_s2k_iterations() throws RopError {
        int ret = lib.rnp_symenc_get_s2k_iterations(seid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    
    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle seid;
    private Stack<Object> outs;
}
