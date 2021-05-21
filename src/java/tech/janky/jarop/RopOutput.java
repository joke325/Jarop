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
import tech.janky.jarop.rop.RopOutputCallBack;


/**
* @version 0.14.0
* @since   0.2
*/
public class RopOutput extends RopObject implements RopOutputCallBack {
    protected RopOutput(RopBind own, RopHandle oid) throws RopError {
        if(oid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.oid = oid;
        this.outputCB = null;
        this.outs = new Stack<Object>();
    }

    protected RopOutput(RopBind own, OutputCallBack outputCB) {
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.oid = null;
        this.outputCB = outputCB;
        this.outs = new Stack<Object>();
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(oid != null) {
            ret = lib.rnp_output_finish(oid);
            int ret2 = lib.rnp_output_destroy(oid);
            ret = (ret==ROPE.RNP_SUCCESS && ret2!=ROPE.RNP_SUCCESS? ret2 : ret);
            oid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return oid;
    }

    protected void Attach(RopHandle oid)  throws RopError {
        if(oid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.oid = oid;
    }

    public boolean OutputWriteCallBack(Object ctx, RopHandle buf, long len) {
        if(outputCB != null && buf != null && len > 0)
            return outputCB.WriteCallBack(ctx, new RopData(own.get(), buf, len));
        return false;
    }
    public void OutputCloseCallBack(Object ctx) {
        if(outputCB != null)
            outputCB.WCloseCallBack(ctx);
    }

    // API

    public RopOutput output_to_armor(String type, int tag) throws RopError {
        int ret = lib.rnp_output_to_armor(oid, outs, type);
        RopOutput arm = new RopOutput(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(arm, tag);
        return arm;
    }
    public RopOutput output_to_armor(String type) throws RopError {
        return output_to_armor(type, 0);
    }
    public RopData memory_get_buf(boolean doCopy) throws RopError {
        int ret = lib.rnp_output_memory_get_buf(oid, outs, outs, doCopy);
        long len = Util.PopLong(lib, outs, ret, false);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), len);
        if(doCopy)
            own.get().PutObj(data, 0);
        return data;
    }
    public long write(RopData data) throws RopError {
        int ret = lib.rnp_output_write(oid, data.getDataObj(), data.getDataLen(), outs);
        return Util.PopLong(lib, outs, ret, true);
    }

    public void armor_set_line_length(long llen) throws RopError {
        int ret = lib.rnp_output_armor_set_line_length(oid, llen);
        Util.Return(ret);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle oid;
    private OutputCallBack outputCB;
    private Stack<Object> outs;
}
