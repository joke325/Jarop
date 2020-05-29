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

import java.time.Instant;

import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/**
* @version 0.2
* @since   0.2
*/
public class RopSignSignature {
    public RopSignSignature(RopBind own, RopHandle sgid) throws RopError {
        if(sgid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.lib = own.getLib();
        this.sgid = sgid;
    }

    public RopHandle getHandle() {
        return sgid;
    }

    // API
    
    public void set_hash(String hash) throws RopError {
        int ret = lib.rnp_op_sign_signature_set_hash(sgid, hash);
        Util.Return(ret);
    }
    public void set_creation_time(Instant create) throws RopError {
        int ret = lib.rnp_op_sign_signature_set_creation_time(sgid, Util.Datetime2TS(create));
        Util.Return(ret);
    }
    public void set_expiration_time(Instant expires) throws RopError {
        int ret = lib.rnp_op_sign_signature_set_expiration_time(sgid, Util.Datetime2TS(expires));
        Util.Return(ret);
    }
    
    private RopLib lib;
    private RopHandle sgid;
}
