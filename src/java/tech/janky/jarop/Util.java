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
import java.time.Instant;
import java.time.Duration;

import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.RopLib;
import tech.janky.jarop.rop.ROPE;


/**
* @version 0.2
* @since   0.2
*/
class Util {
    public final static String GetRopString(RopLib rop, int ret, RopHandle ropStr, boolean freeBuf) throws RopError {
        String sval = RopHandle.Str(ropStr);
        if(freeBuf)
            rop.rnp_buffer_destroy(ropStr);
        if(ret != ROPE.RNP_SUCCESS)
            throw new RopError(ret);
        return sval;
    }
    
    public final static RopHandle PopHandle(RopLib rop, Stack<Object> vals, int err, boolean fin) throws RopError {
        Object obj = (vals.size()>0? vals.pop() : null);
        if(fin)
            vals.clear();
        if(err != ROPE.RNP_SUCCESS)
            throw new RopError(err);
        if(!(obj instanceof RopHandle))
            throw new RopError(RopBind.ROP_ERROR_INTERNAL);
        return (RopHandle)obj;
    }

    public final static String PopString(RopLib rop, Stack<Object> vals, int err, boolean fin) throws RopError {
        RopHandle hnd = PopHandle(rop, vals, err, fin);
        return GetRopString(rop, err, hnd, true);
    }	

    public final static String[] PopStrings(RopLib rop, Stack<Object> vals, int err, int count, boolean fin) throws RopError {
        String[] output = new String[count];
        int idx = count;
        while(idx-- > 0)
            output[idx] = PopString(rop, vals, err, idx==0? fin : false);
        return output;
    }

    public final static int PopInt(RopLib rop, Stack<Object> vals, int err, boolean fin) throws RopError {
        Object obj = (vals.size()>0? vals.pop() : null);
        if(fin)
            vals.clear();
        if(err != ROPE.RNP_SUCCESS)
            throw new RopError(err);
        if(!(obj instanceof Integer))
            throw new RopError(RopBind.ROP_ERROR_INTERNAL);
        return ((Integer)obj).intValue();
    }

    public final static long PopLong(RopLib rop, Stack<Object> vals, int err, boolean fin) throws RopError {
        Object obj = (vals.size()>0? vals.pop() : null);
        if(fin)
            vals.clear();
        if(err != ROPE.RNP_SUCCESS)
            throw new RopError(err);
        if(!(obj instanceof Long))
            throw new RopError(RopBind.ROP_ERROR_INTERNAL);
        return ((Long)obj).longValue();
    }

    public final static boolean PopBool(RopLib rop, Stack<Object> vals, int err, boolean fin) throws RopError {
        return PopInt(rop, vals, err, fin) != 0;
    }

    public final static void Return(int err) throws RopError {
        if(err != ROPE.RNP_SUCCESS)
            throw new RopError(err);
    }	

    public final static long Datetime2TS(Instant dtime) {
        return dtime!=null? dtime.getEpochSecond() : 0;
    }

    public final static long TimeDelta2Sec(Duration tdtime) {
        return tdtime!=null? tdtime.getSeconds() : 0;
    }
}
