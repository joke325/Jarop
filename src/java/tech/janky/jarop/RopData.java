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

import java.util.Arrays;

import tech.janky.jarop.rop.ROPE;
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;


/** 
* Encapsulates String, byte[], RopHandle data
* @version 0.2
* @since   0.2
*/
public class RopData extends RopObject {
    protected RopData(RopBind own, RopHandle hnd, long dataLen) {
        this.lib = own.getLib();
        this.hnd = hnd;
        this.dataLen = dataLen;
        this.sdata = null;
        this.bdata = null;
    }
    
    /** 
    * Constructor
    */
    public RopData(String data) {
        this.lib = null;
        this.hnd = null;
        this.dataLen = 0;
        this.sdata = data;
        this.bdata = null;
    }

    /** 
    * Constructor
    */
    public RopData(byte[] data) {
        this.lib = null;
        this.hnd = null;
        this.dataLen = 0;
        this.sdata = null;
        this.bdata = data;
    }

    protected int Close() {
        int ret = ROPE.RNP_SUCCESS;
        if(hnd != null) {
            lib.rnp_buffer_destroy(hnd);
            hnd = null;
            dataLen = 0;
        }
        return ret;
    }

    /**
    * @return String data
    */
    public String getString() {
        if(sdata != null)
            return sdata;
        if(hnd != null && !hnd.isNull()) {
            String str = RopHandle.Str(hnd);
            return str!=null&&0<dataLen&&dataLen<str.length()? str.substring(0, (int)dataLen) : str;
        }
        return null;
    }

    /**
    * @return byte[] data
    */
    public byte[] getBytes(long len) {
        if(bdata != null)
            return !(0<len&&len<bdata.length)? bdata : Arrays.copyOfRange(bdata, 0, (int)len);
        if(hnd != null && !hnd.isNull())
            return hnd.toBytes(len==0||(0<dataLen&&dataLen<len)? dataLen : len);
        return null;
    }

    /**
    * @return byte[] data
    */
    public byte[] getBytes() {
        return getBytes(0);
    }

    /**
    * @return RopHandle data
    */
    public RopHandle getHandle() {
        return hnd;
    }

    /**
    * @return length of data
    */
    public long getLength() {
        return getDataLen();
    }

    public boolean isNull() {
        if(hnd != null)
            return hnd.isNull();
        return sdata == null && bdata == null;
    }
    
    protected Object getDataObj() {
        if(sdata != null)
            return sdata;
        if(bdata != null)
            return bdata;
        return hnd;
    }

    protected long getDataLen() {
        if(sdata != null)
            return sdata.length();
        if(bdata != null)
            return bdata.length;
        return dataLen;
    }

    private RopLib lib;
    private RopHandle hnd;
    private long dataLen;
    private String sdata;
    private byte[] bdata;
}
