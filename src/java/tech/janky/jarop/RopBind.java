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

import java.util.List;
import java.util.LinkedList;
import java.util.Set;
import java.util.TreeSet;
import java.util.TreeMap;
import java.util.Stack;

import tech.janky.jarop.rop.RopLib;
import tech.janky.jarop.rop.ROPE;
import tech.janky.jarop.rop.RopHandle;
import tech.janky.jarop.rop.ROPD;


/**
* Root object of bindings for the RNP OpenPGP library
* @version 0.2
* @since   0.2
*/
public class RopBind {
    private int cnt;
    private RopLib lib;
    private LinkedList<Integer> tags;
    private TreeMap<Integer, TreeMap<RopObject, Integer> > t2objs;  //tag->set
    private Stack<Object> outs;

    private void IniRopBind(boolean checkLibVer) throws RopError {
        this.cnt = 1;
        this.lib = new RopLib();
        this.tags = new LinkedList<Integer>(); 
        this.tags.add(new Integer(this.cnt)); 
        this.t2objs = new TreeMap<Integer, TreeMap<RopObject, Integer> >();
        this.outs = new Stack<Object>();
        if(checkLibVer && !(this.lib.rnp_version() >= this.lib.rnp_version_for(0, 9, 0)))
            throw new RopError(ROP_ERROR_LIBVERSION);
    }

    /** 
    * Constructor
    */
    public RopBind() throws RopError {
        IniRopBind(true);
    }

    /** 
    * Constructor
    */
    public RopBind(boolean checkLibVer) throws RopError {
        IniRopBind(checkLibVer);
    }	

    /** 
    * Terminates the instance
    */
    public void Close() throws RopError {
        clear();
        if(lib != null)
            lib.CleanUp();
        lib = null;
    }	

    /** 
    * Access to the lower level interface, do not use unless inevitable!
    */
    public RopLib getLib() { return lib; }
    

    // API

    public String default_homedir() throws RopError {
        int ret = lib.rnp_get_default_homedir(outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String version_string() {
        return lib.rnp_version_string();
    }
    public String version_string_full() {
        return lib.rnp_version_string_full();
    }
    public int version() {
        return lib.rnp_version();
    }
    public long version_commit_timestamp() {
        return lib.rnp_version_commit_timestamp();
    }
    public String[] get_homedir_info(String homedir) throws RopError {
        int ret = lib.rnp_detect_homedir_info(homedir, outs, outs, outs, outs);
        return Util.PopStrings(lib, outs, ret, 4, true);
    }
    public int version_for(int major, int minor, int patch) {
        return lib.rnp_version_for(major, minor, patch);
    }
    public int version_major(int version) {
        return lib.rnp_version_major(version);
    }
    public int version_minor(int version) {
        return lib.rnp_version_minor(version);
    }
    public int version_patch(int version) {
        return lib.rnp_version_patch(version);
    }
    public String result_to_string(int result) {
        return lib.rnp_result_to_string(result);
    }
    public int enable_debug(String file) {
        return lib.rnp_enable_debug(file);
    }
    public int disable_debug() {
        return lib.rnp_disable_debug();
    }
    public boolean supports_feature(String type, String name) throws RopError {
        int ret = lib.rnp_supports_feature(type, name, outs);
        return Util.PopBool(lib, outs, ret, true);
    }
    public String supported_features(String type) throws RopError {
        int ret = lib.rnp_supported_features(type, outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public String detect_key_format(RopData buf) throws RopError {
        int ret = lib.rnp_detect_key_format(buf.getDataObj(), buf.getDataLen(), outs);
        return Util.PopString(lib, outs, ret, true);
    }
    public int calculate_iterations(String hash, int msec) throws RopError {
        int ret = lib.rnp_calculate_iterations(hash, msec, outs);
        return Util.PopInt(lib, outs, ret, true);
    }
    
    public RopSession create_session(String pubFormat, String secFormat, int tag) throws RopError {
        int ret = lib.rnp_ffi_create(outs, pubFormat, secFormat);
        RopSession ses = new RopSession(this, Util.PopHandle(lib, outs, ret, true));
        PutObj(ses, tag);
        return ses;
    }
    public RopSession create_session(String pubFormat, String secFormat) throws RopError {
        return create_session(pubFormat, secFormat, 0);
    }    

    public RopInput create_input(RopData buf, boolean doCopy, int tag) throws RopError {
        int ret = lib.rnp_input_from_memory(outs, buf.getDataObj(), buf.getDataLen(), doCopy);
        RopInput inp = new RopInput(this, Util.PopHandle(lib, outs, ret, true));
        PutObj(inp, tag);
        return inp;
    }
    public RopInput create_input(RopData buf, boolean doCopy) throws RopError {
        return create_input(buf, doCopy, 0);
    }
    public RopInput create_input(String path, int tag) throws RopError {
        int ret = lib.rnp_input_from_path(outs, path);
        RopInput inp = new RopInput(this, Util.PopHandle(lib, outs, ret, true));
        PutObj(inp, tag);
        return inp;
    }
    public RopInput create_input(String path) throws RopError {
        return create_input(path, 0);
    }
    public RopInput create_input(InputCallBack inputCB, Object app_ctx, int tag) throws RopError {
        RopInput inp = new RopInput(this, inputCB);
        int ret = lib.rnp_input_from_callback(outs, inp, app_ctx);
        inp.Attach(Util.PopHandle(lib, outs, ret, true));
        PutObj(inp, tag);
        return inp;
    }
    public RopInput create_input(InputCallBack inputCB, Object app_ctx) throws RopError {
        return create_input(inputCB, app_ctx, 0);
    }
    
    public RopOutput create_output(String toFile, boolean overwrite, boolean random, int tag) throws RopError {
        int flags = (overwrite? ROPD.RNP_OUTPUT_FILE_OVERWRITE : 0);
        flags |= (random? ROPD.RNP_OUTPUT_FILE_RANDOM : 0);
        int ret = lib.rnp_output_to_file(outs, toFile, flags);
        RopOutput outp = new RopOutput(this, Util.PopHandle(lib, outs, ret, true));
        PutObj(outp, tag);
        return outp;
    }
    public RopOutput create_output(String toFile, boolean overwrite, boolean random) throws RopError {
        return create_output(toFile, overwrite, random, 0);
    }
    public RopOutput create_output(String toPath, int tag) throws RopError {
        int ret = lib.rnp_output_to_path(outs, toPath);
        RopOutput outp = new RopOutput(this, Util.PopHandle(lib, outs, ret, true));
        PutObj(outp, tag);
        return outp;
    }    
    public RopOutput create_output(String toPath) throws RopError {
        return create_output(toPath, 0);
    }    
    public RopOutput create_output() throws RopError {
        int ret = lib.rnp_output_to_null(outs);
        RopOutput outp = new RopOutput(this, Util.PopHandle(lib, outs, ret, true));
        PutObj(outp, 0);
        return outp;
    }
    public RopOutput create_output(long maxAlloc, int tag) throws RopError {
        int ret = lib.rnp_output_to_memory(outs, maxAlloc);
        RopOutput outp = new RopOutput(this, Util.PopHandle(lib, outs, ret, true));
        PutObj(outp, tag);
        return outp;
    }
    public RopOutput create_output(long maxAlloc) throws RopError {
        return create_output(maxAlloc, 0);
    }    
    public RopOutput create_output(OutputCallBack outputCB, Object app_ctx, int tag) throws RopError {
        RopOutput outp = new RopOutput(this, outputCB);
        int ret = lib.rnp_output_to_callback(outs, outp, app_ctx);
        outp.Attach(Util.PopHandle(lib, outs, ret, true));
        PutObj(outp, tag);
        return outp;
    }
    public RopOutput create_output(OutputCallBack outputCB, Object app_ctx) throws RopError {
        return create_output(outputCB, app_ctx, 0);
    }    

    /**
    * Tagging of allocated objects
    * @return tag of subsequestly allocated objects
    */
    public int tagging(int tag) {
        cnt++;
        tags.add(new Integer(tag!=0? tag : cnt));
        return tags.getLast().intValue();
    }
    public int tagging() {
        return tagging(0);
    }

    /**
    * Deletes tagged / specified objects
    */
    public void drop(int tag, Object object, Object[] objects, Integer from) throws RopError {
        int ret = ROPE.RNP_SUCCESS;
        
        // collect tags to delete
        List<Integer> dtags = new LinkedList<Integer>();
        if(from != null) {
            int idx = tags.indexOf(from);
            if(!(idx < 0))
                dtags = tags.subList(idx, tags.size());
        } else if(tag == 0 && tags.size() > 1)
            dtags.add(tags.getLast());
        else
            dtags.add(new Integer(tag));

        // collect objects to delete
        Set<RopObject> objset = new TreeSet<RopObject>();
        if(objects != null)
            for(Object obj : objects)
                if(obj instanceof RopObject)
                    objset.add((RopObject)obj);
        if(object != null && object instanceof RopObject)
            objset.add((RopObject)object);

        // delete the dtags and objset conjuction
        TreeMap<Integer, RopObject> sorted = new TreeMap<Integer, RopObject>();
        for(Integer tg : (tag>=0? dtags : tags)) {
            TreeMap<RopObject, Integer> objs = t2objs.get(tg);
            if(objs != null) {
                Set<RopObject> dellist = objs.keySet();
                if(objset.size() > 0) {
                    dellist = new TreeSet<RopObject>(dellist);
                    dellist.retainAll(objset);
                }
                sorted.clear();
                for(RopObject obj : dellist)
                    sorted.put(objs.get(obj), obj);
                for(Integer nn : sorted.descendingKeySet()) {
                    RopObject obj = sorted.get(nn);
                    int err = obj.Close();
                    ret = (ret==ROPE.RNP_SUCCESS? err : ret);
                    objs.remove(obj);
                }
                if(objs.size() == 0)
                    t2objs.remove(tg);
            }
            
            // delete obsolete tags
            if(!t2objs.containsKey(tg)) {
                tags.remove(tg);
                if(tags.size() == 1)
                    this.cnt = tags.getLast().intValue();
            }
        }

        if(ret != ROPE.RNP_SUCCESS)
            throw new RopError(ret);
    }
    public void drop(int tag) throws RopError {
        drop(tag, null, null, null);
    }
    public void drop() throws RopError {
        drop(0);
    }
    public void drop_from(int from) throws RopError {
        drop(0, null, null, new Integer(from));
    }
    public void drop(Object object) throws RopError {
        drop(0, object, null, null);
    }
    public void drop(Object[] objects) throws RopError {
        drop(0, null, objects, null);
    }

    /**
    * To delete all objects
    */
    public void clear() throws RopError {
        drop(-1);
    }

    // Tools

    protected void PutObj(RopObject obj, int tag) {
        Integer otag = (tag!=0? new Integer(tag) : tags.getLast());
        TreeMap<RopObject, Integer> objs = t2objs.get(otag);
        if(objs == null)
            t2objs.put(otag, objs = new TreeMap<RopObject, Integer>());
        this.cnt++;
        objs.put(obj, new Integer(this.cnt));
    }

    /**
    * Describes this object
    */
    @Override
    public String toString() {
        return "tags = " + tags.size() + "\nt2objs = " + t2objs.size();
    }

    // Constants

    public final static String KEYSTORE_GPG = ROPD.RNP_KEYSTORE_GPG;
    public final static String KEYSTORE_KBX = ROPD.RNP_KEYSTORE_KBX;
    public final static String KEYSTORE_G10 = ROPD.RNP_KEYSTORE_G10;
    public final static String KEYSTORE_GPG21 = ROPD.RNP_KEYSTORE_GPG21;

    public final static String ALG_HASH_MD5 = ROPD.RNP_ALGNAME_MD5;
    public final static String ALG_HASH_SHA1 = ROPD.RNP_ALGNAME_SHA1;
    public final static String ALG_HASH_SHA256 = ROPD.RNP_ALGNAME_SHA256;
    public final static String ALG_HASH_SHA384 = ROPD.RNP_ALGNAME_SHA384;
    public final static String ALG_HASH_SHA512 = ROPD.RNP_ALGNAME_SHA512;
    public final static String ALG_HASH_SHA224 = ROPD.RNP_ALGNAME_SHA224;
    public final static String ALG_HASH_SHA3_256 = ROPD.RNP_ALGNAME_SHA3_256;
    public final static String ALG_HASH_SHA3_512 = ROPD.RNP_ALGNAME_SHA3_512;
    public final static String ALG_HASH_RIPEMD160 = ROPD.RNP_ALGNAME_RIPEMD160;
    public final static String ALG_HASH_SM3 = ROPD.RNP_ALGNAME_SM3;
    public final static String ALG_HASH_DEFAULT = ALG_HASH_SHA256;
    public final static String ALG_SYMM_IDEA = ROPD.RNP_ALGNAME_IDEA;
    public final static String ALG_SYMM_TRIPLEDES = ROPD.RNP_ALGNAME_TRIPLEDES;
    public final static String ALG_SYMM_CAST5 = ROPD.RNP_ALGNAME_CAST5;
    public final static String ALG_SYMM_BLOWFISH = ROPD.RNP_ALGNAME_BLOWFISH;
    public final static String ALG_SYMM_TWOFISH = ROPD.RNP_ALGNAME_TWOFISH;
    public final static String ALG_SYMM_AES_128 = ROPD.RNP_ALGNAME_AES_128;
    public final static String ALG_SYMM_AES_192 = ROPD.RNP_ALGNAME_AES_192;
    public final static String ALG_SYMM_AES_256 = ROPD.RNP_ALGNAME_AES_256;
    public final static String ALG_SYMM_CAMELLIA_128 = ROPD.RNP_ALGNAME_CAMELLIA_128;
    public final static String ALG_SYMM_CAMELLIA_192 = ROPD.RNP_ALGNAME_CAMELLIA_192;
    public final static String ALG_SYMM_CAMELLIA_256 = ROPD.RNP_ALGNAME_CAMELLIA_256;
    public final static String ALG_SYMM_SM4 = ROPD.RNP_ALGNAME_SM4;
    public final static String ALG_SYMM_DEFAULT = ALG_SYMM_AES_256;
    public final static String ALG_ASYM_RSA = ROPD.RNP_ALGNAME_RSA;
    public final static String ALG_ASYM_ELGAMAL = ROPD.RNP_ALGNAME_ELGAMAL;
    public final static String ALG_ASYM_DSA = ROPD.RNP_ALGNAME_DSA;
    public final static String ALG_ASYM_ECDH = ROPD.RNP_ALGNAME_ECDH;
    public final static String ALG_ASYM_ECDSA = ROPD.RNP_ALGNAME_ECDSA;
    public final static String ALG_ASYM_EDDSA = ROPD.RNP_ALGNAME_EDDSA;
    public final static String ALG_ASYM_SM2 = ROPD.RNP_ALGNAME_SM2;
    public final static String ALG_PLAINTEXT = ROPD.RNP_ALGNAME_PLAINTEXT;
    public final static String ALG_CRC24 = ROPD.RNP_ALGNAME_CRC24;

    public final static int ROP_ERROR_BAD_PARAMETERS = 0x80000000;
    public final static int ROP_ERROR_LIBVERSION = 0x80000001;
    public final static int ROP_ERROR_INTERNAL = 0x80000002;
    public final static int ROP_ERROR_NULL_HANDLE = 0x80000003;


    public static void main(String[] args) throws RopError {
        // A trivial test
        try {
            throw new RopError(0);
        } catch (RopError ex) {
            System.out.println("Starting:");
        }
        RopBind rop = null;
        try {
            rop = new RopBind();
            System.out.println(rop.version_string_full());
            RopSession ses = rop.create_session("GPG", "GPG");
            System.out.println("Session: " + ses.toString());
            System.out.println("Done.");
        } catch(RopError ex) {
            System.out.println(ex);
        } finally {
            if(rop != null)
                rop.Close();
        }
    }
}
