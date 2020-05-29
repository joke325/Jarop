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

package tech.janky.jarop.examples;

// Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/verify.c

import java.lang.ref.WeakReference;

import tech.janky.jarop.RopBind;
import tech.janky.jarop.RopSession;
import tech.janky.jarop.RopKey;
import tech.janky.jarop.RopInput;
import tech.janky.jarop.RopOutput;
import tech.janky.jarop.RopOpVerify;
import tech.janky.jarop.RopVeriSignature;
import tech.janky.jarop.RopData;
import tech.janky.jarop.RopError;
import tech.janky.jarop.SessionKeyCallBack;


public class Verify implements SessionKeyCallBack {
    // an example key provider
    public void KeyCallBack(RopSession ses, Object ctx, String identifier_type, String identifier, boolean secret) {
        if(identifier_type.compareTo("keyid") == 0) {
            String filename = String.format("key-%s-%s.asc", identifier, secret? "sec" : "pub");
            String err_desc = null;
            try {
                WeakReference<RopBind> rop = ses.getBind();
                err_desc = String.format("failed to open key file %s", filename);
                RopInput input = rop.get().create_input(filename);

                err_desc = String.format("failed to load key from file %s", filename);
                ses.load_keys(RopBind.KEYSTORE_GPG, input, true, true);
            } catch(RopError ex) {
                System.out.println(err_desc);
            }
        }
    }

    private void verify(RopBind rop) throws RopError {
        int alt = rop.tagging();
        try {
            // initialize
            RopSession ses = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG);

            // we do not load any keys here since we'll use key provider
            ses.set_key_provider(this, null);

            String err_desc = null;
            RopOutput output = null;
            try {
                // create file input and memory output objects for the signed message
                // and verified message
                err_desc = "Failed to open file 'signed.asc'. Did you run the sign example?";
                RopInput input = rop.create_input("signed.asc");

                err_desc = "Failed to create output object";
                output = rop.create_output(0);

                err_desc = "Failed to create verification context";
                RopOpVerify verify = ses.op_verify_create(input, output);

                err_desc = "Failed to execute verification operation";
                verify.execute();

                // now check signatures and get some info about them
                err_desc = "Failed to get signature count";
                int sigcount = verify.signature_count();

                for(int idx = 0; idx < sigcount; idx++) {
                    rop.tagging();

                    err_desc = String.format("Failed to get signature %d", idx);
                    RopVeriSignature sig = verify.get_signature_at(idx);

                    err_desc = String.format("failed to get signature's %d key", idx);
                    RopKey key = sig.get_key();

                    err_desc = String.format("failed to get key id %d", idx);

                    System.out.println(String.format("Status for signature from key %s : %d", key.keyid(), sig.status()));
                    rop.drop();
                }
            } catch(RopError ex) {
                System.out.println(err_desc);
                throw ex;
            }

            // get the verified message from the output structure
            RopData buf = output.memory_get_buf(false);
            System.out.println(String.format("Verified message: %s", buf.getString()));
        } finally {
            rop.drop_from(alt);
        }
    }
    
    public void execute() throws RopError {
        RopBind rop = new RopBind();
        try {
            verify(rop);
        } finally {
            rop.Close();
        }
    }

    public static void main(String[] args) throws RopError {
        Verify ver = new Verify();
        ver.execute();
    }
}
