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

import tech.janky.jarop.rop.ROPE;
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/** 
* @version 0.2
* @since   0.2
*/
public class RopIdIterator extends RopObject {
    protected RopIdIterator(RopBind own, RopHandle iiid) throws RopError {
        if(iiid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.lib = own.getLib();
        this.iiid = iiid;
        this.outs = new Stack<Object>();
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(iiid != null) {
            ret = lib.rnp_identifier_iterator_destroy(iiid);
            iiid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return iiid;
    }

    public String next() throws RopError {
        int ret = lib.rnp_identifier_iterator_next(iiid, outs);
        RopHandle hnd = Util.PopHandle(lib, outs, ret, true);
        return Util.GetRopString(lib, ret, hnd, false);
    }
    
    private RopLib lib;
    private RopHandle iiid;
    private Stack<Object> outs;
}
