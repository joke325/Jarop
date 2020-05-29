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

package tech.janky.jarop.rop;


/**
* @version 0.2
* @since   0.2
*/
final public class RopHandle implements Comparable<RopHandle> {
    protected RopHandle(int type, boolean isNull, byte[] data) {
        this.type = type;
        this.isnull = isNull;
        this.data = data;
        source = null;
        src_i = 0;
    }

    public static RopHandle Cast2Str(RopHandle hnd) {
        return new RopHandle(1, hnd.isnull, hnd.data);
    }

    public static String Str(RopHandle hnd) {
        return hnd!=null? Cast2Str(hnd).toString() : null;
    }

    public boolean isNull() {
        return isnull;
    }

    @Override
    public native String toString();
    public native byte[] toBytes(long len);
    public native int WriteString(Object buf, int maxLen);
    public native long WriteBytes(byte[] buf, long len);
    
    public int compareTo(RopHandle rh) {
        int comp = 0;
        int len1 = data.length, len2 = rh.data.length;
        for(int idx = 0, len = Math.min(len1, len2); comp == 0 && idx < len; idx++)
            comp = (data[idx]==rh.data[idx]? 0 : (data[idx]<rh.data[idx]? -1 : 1));
        return comp==0&&len1!=len2? (len1<len2? -1 : 1) : comp;
    }

    protected int type;
    protected boolean isnull;
    protected byte[] data;
    protected Object source;
    protected int src_i;
}
