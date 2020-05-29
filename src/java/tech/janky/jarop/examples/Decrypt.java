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

// Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/decrypt.c

import tech.janky.jarop.RopBind;
import tech.janky.jarop.RopSession;
import tech.janky.jarop.RopKey;
import tech.janky.jarop.RopInput;
import tech.janky.jarop.RopOutput;
import tech.janky.jarop.RopError;
import tech.janky.jarop.SessionPassCallBack;


public class Decrypt implements SessionPassCallBack {
    public static String message = "Dummy";

    public SessionPassCallBack.Ret PassCallBack(RopSession ses, Object ctx, RopKey key, String pgpCtx, int bufLen) {
        if(pgpCtx.compareTo("decrypt (symmetric)") == 0)
            return new SessionPassCallBack.Ret(true, "encpassword");
        if(pgpCtx.compareTo("decrypt") == 0)
            return new SessionPassCallBack.Ret(true, "password");
        return new SessionPassCallBack.Ret(false, null);
    }

    private void decrypt(RopBind rop, boolean usekeys) throws RopError {
        int alt = rop.tagging();
        try {
            // initialize FFI object
            RopSession ses = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG);

            // check whether we want to use key or password for decryption
            if(usekeys) {
                RopInput keyfile = null;
                try {
                    // load secret keyring, as it is required for public-key decryption. However, you may
                    // need to load public keyring as well to validate key's signatures.
                    keyfile = rop.create_input("secring.pgp");
                    // we may use secret=True and public=True as well
                    ses.load_keys_secret(RopBind.KEYSTORE_GPG, keyfile);
                } catch(RopError ex) {
                    System.out.println("Failed to read secring");
                    throw ex;
                } finally {
                    rop.drop(keyfile);
                }
            }

            // set the password provider
            ses.set_pass_provider(this, null);
            String buf = null;
            try {
                // create file input and memory output objects for the encrypted message and decrypted
                // message
                RopInput input = rop.create_input("encrypted.asc");
                RopOutput output = rop.create_output(0);
                ses.decrypt(input, output);
                // get the decrypted message from the output structure
                buf = output.memory_get_buf(false).getString();
            } catch(RopError ex) {
                System.out.println("Public-key decryption failed");
                throw ex;
            }

            System.out.println(String.format("Decrypted message (%s):\n%s\n", usekeys? "with key" : "with password", buf));
            Decrypt.message = buf;
        } finally {
            rop.drop_from(alt);
        }
    }
    
    public void execute() throws RopError {
        RopBind rop = new RopBind();
        try {
            decrypt(rop, true);
            decrypt(rop, false);
        } finally {
            rop.Close();
        }
    }

    public static void main(String[] args) throws RopError {
        Decrypt dec = new Decrypt();
        dec.execute();
    }
}
