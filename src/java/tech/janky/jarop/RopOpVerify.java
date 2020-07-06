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
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/**
* @version 0.3.0
* @since   0.2
*/
public class RopOpVerify extends RopObject {
    protected RopOpVerify(RopBind own, RopHandle opid) throws RopError {
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
            ret = lib.rnp_op_verify_destroy(opid);
            opid = null;
        }
        return ret;
    }
    
    public RopHandle getHandle() {
        return opid;
    }
    
    // API

    public int signature_count() throws RopError {
        int ret = lib.rnp_op_verify_get_signature_count(opid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public void execute() throws RopError {
        int ret = lib.rnp_op_verify_execute(opid);
        Util.Return(ret);
    }
    public RopVeriSignature get_signature_at(int idx) throws RopError {
        int ret = lib.rnp_op_verify_get_signature_at(opid, idx, outs);
        return new RopVeriSignature(own.get(), Util.PopHandle(lib, outs, ret, true));
    }
    public FileInfo get_file_info() throws RopError {
        int ret = lib.rnp_op_verify_get_file_info(opid, outs, outs);
        Instant mtime = Instant.ofEpochSecond(Util.PopLong(lib, outs, ret, false));
        return new FileInfo(Util.PopString(lib, outs, ret, true), mtime);
    }

    public final class ProtectionInfo {
        public String mode;
        public String cipher;
        public boolean valid;
        public ProtectionInfo(String mode, String cipher, boolean valid) { this.mode = mode; this.cipher = cipher; this.valid = valid; }
    }    
    public ProtectionInfo get_protection_info() throws RopError {
        int ret = lib.rnp_op_verify_get_protection_info(opid, outs, outs, outs);
        boolean valid = Util.PopBool(lib, outs, ret, false);
        String cipher = Util.PopString(lib, outs, ret, false);
        return new ProtectionInfo(Util.PopString(lib, outs, ret, true), cipher, valid);
    }
    public int get_recipient_count() throws RopError {
        int ret = lib.rnp_op_verify_get_recipient_count(opid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public RopRecipient get_used_recipient(int tag) throws RopError {
        int ret = lib.rnp_op_verify_get_used_recipient(opid, outs);
        RopRecipient recp = new RopRecipient(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(recp, tag);
        return recp;
    }
    public RopRecipient get_used_recipient() throws RopError { 
        return get_used_recipient(0); 
    }
    public RopRecipient get_recipient_at(int idx, int tag) throws RopError {
        int ret = lib.rnp_op_verify_get_recipient_at(opid, idx, outs);
        RopRecipient recp = new RopRecipient(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(recp, tag);
        return recp;
    }
    public RopRecipient get_recipient_at(int idx) throws RopError {
        return get_recipient_at(idx, 0);
    }
    public int get_symenc_count() throws RopError {
        int ret = lib.rnp_op_verify_get_symenc_count(opid, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    public RopSymEnc get_used_symenc(int tag) throws RopError {
        int ret = lib.rnp_op_verify_get_used_symenc(opid, outs);
        RopSymEnc senc = new RopSymEnc(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(senc, tag);
        return senc;
    }
    public RopSymEnc get_used_symenc() throws RopError {
        return get_used_symenc(0);
    }
    public RopSymEnc get_symenc_at(int idx, int tag) throws RopError {
        int ret = lib.rnp_op_verify_get_symenc_at(opid, idx, outs);
        RopSymEnc senc = new RopSymEnc(own.get(), Util.PopHandle(lib, outs, ret, true));
        own.get().PutObj(senc, tag);
        return senc;
    }
    public RopSymEnc get_symenc_at(int idx) throws RopError {
        return get_symenc_at(idx, 0);
    }
    
    private WeakReference<RopBind> own;
    private RopLib lib;
    private RopHandle opid;
    private Stack<Object> outs;
    
    public class FileInfo {
        public FileInfo(String fileName, Instant mtime) { this.fileName = fileName; this.mtime = mtime; }
        public String fileName;
        public Instant mtime;
    }
}
