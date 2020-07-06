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
import tech.janky.jarop.rop.ROPD;
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;
import tech.janky.jarop.rop.RopInputCallBack.Ret;
import tech.janky.jarop.rop.RopInputCallBack;


/** 
* @version 0.3.0
* @since   0.2
*/
public class RopInput extends RopObject implements RopInputCallBack {
    protected RopInput(RopBind own, RopHandle iid) throws RopError {
        if(iid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.iid = iid;
        this.inputCB = null;
        this.outs = new Stack<Object>();
    }

    protected RopInput(RopBind own, InputCallBack inputCB) {
        this.own = new WeakReference<RopBind>(own);
        this.lib = own.getLib();
        this.iid = null;
        this.inputCB = inputCB;
        this.outs = new Stack<Object>();
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(iid != null) {
            ret = lib.rnp_input_destroy(iid);
            iid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return iid;
    }

    protected void Attach(RopHandle iid)  throws RopError {
        if(iid.isNull())
            throw new RopError(RopBind.ROP_ERROR_NULL_HANDLE);
        this.iid = iid;
    }
    
    public RopInputCallBack.Ret InputReadCallBack(Object ctx, long len) {
        if(inputCB != null) {
            byte[] data = inputCB.ReadCallBack(ctx, len);
            if(data != null)
                return new RopInputCallBack.Ret(data, data.length);
        }
        return new RopInputCallBack.Ret(null, 0);
    }

    public void InputCloseCallBack(Object ctx) {
        if(inputCB != null)
            inputCB.RCloseCallBack(ctx);
    }

    // API

    public RopData dump_packets_to_json(boolean mpi, boolean raw, boolean grip) throws RopError {
        int flags = (mpi? ROPD.RNP_JSON_DUMP_MPI : 0);
        flags |= (raw? ROPD.RNP_JSON_DUMP_RAW : 0);
        flags |= (grip? ROPD.RNP_JSON_DUMP_GRIP : 0);
        int ret = lib.rnp_dump_packets_to_json(iid, flags, outs);
        RopData data = new RopData(own.get(), Util.PopHandle(lib, outs, ret, true), 0);
        own.get().PutObj(data, 0);
        return data;
    }
    public RopData dump_packets_to_json() throws RopError {
        return dump_packets_to_json(false, false, false);
    }
    public RopData dump_packets_to_json_mpi() throws RopError {
        return dump_packets_to_json(true, false, false);
    }
    public RopData dump_packets_to_json_raw() throws RopError {
        return dump_packets_to_json(false, true, false);
    }
    public RopData dump_packets_to_json_grip() throws RopError {
        return dump_packets_to_json(false, false, true);
    }
    public void dump_packets_to_output(RopOutput output, boolean mpi, boolean raw, boolean grip) throws RopError {
        int flags = (mpi? ROPD.RNP_DUMP_MPI : 0);
        flags |= (raw? ROPD.RNP_DUMP_RAW : 0);
        flags |= (grip? ROPD.RNP_DUMP_GRIP : 0);
        int ret = lib.rnp_dump_packets_to_output(iid, output!=null? output.getHandle() : null, flags);
        Util.Return(ret);
    }
    public void dump_packets_to_output_mpi(RopOutput output) throws RopError {
        dump_packets_to_output(output, true, false, false);
    }
    public void dump_packets_to_output_raw(RopOutput output) throws RopError {
        dump_packets_to_output(output, false, true, false);
    }
    public void dump_packets_to_output_grip(RopOutput output) throws RopError {
        dump_packets_to_output(output, false, false, true);
    }
    public void enarmor(RopOutput output, String type) throws RopError {
        int ret = lib.rnp_enarmor(iid, output!=null? output.getHandle() : null, type);
        Util.Return(ret);
    }
    public void dearmor(RopOutput output) throws RopError {
        int ret = lib.rnp_dearmor(iid, output!=null? output.getHandle() : null);
        Util.Return(ret);
    }
    public String guess_contents() throws RopError {
        int ret = lib.rnp_guess_contents(iid, outs);
        return Util.PopString(lib, outs, ret, true);
    }

    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle iid;
    private InputCallBack inputCB;
    private Stack<Object> outs;
}
