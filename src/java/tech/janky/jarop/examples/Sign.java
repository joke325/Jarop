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

// Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/sign.c

import java.time.Instant; 
import java.time.Duration; 

import tech.janky.jarop.RopBind;
import tech.janky.jarop.RopSession;
import tech.janky.jarop.RopKey;
import tech.janky.jarop.RopInput;
import tech.janky.jarop.RopOutput;
import tech.janky.jarop.RopOpSign;
import tech.janky.jarop.RopData;
import tech.janky.jarop.RopError;
import tech.janky.jarop.SessionPassCallBack;


public class Sign implements SessionPassCallBack {
    public static String[] key_ids = new String[] {"Dummy", "Dummy"};
    public static String[] key_fprints = new String[] {"Dummy", "Dummy"};

    // an example pass provider
    public SessionPassCallBack.Ret PassCallBack(RopSession ses, Object ctx, RopKey key, String pgpCtx, int bufLen) {
        return new SessionPassCallBack.Ret(true, "password");
    }

    private void sign(RopBind rop) throws RopError {
        String message = "ROP signing sample message";

        int alt = rop.tagging();
        try {
            // initialize
            RopSession ses = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG);

            RopInput keyfile = null;
            String err_desc = null;
            try {
                // load secret keyring, as it is required for signing. However, you may need
                // to load public keyring as well to validate key's signatures.
                err_desc = "Failed to open secring.pgp. Did you run Generate.java sample?";
                keyfile = rop.create_input("secring.pgp");

                // we may use public=True and secret=True as well
                err_desc = "Failed to read secring.pgp";
                ses.load_keys_secret(RopBind.KEYSTORE_GPG, keyfile);
            } catch(RopError ex) {
                System.out.println(err_desc);
                throw ex;
            } finally {
                rop.drop(keyfile);
            }

            // set the password provider - we'll need password to unlock secret keys
            ses.set_pass_provider(this, null);

            // create file input and memory output objects for the encrypted message
            // and decrypted message
            RopOpSign sign = null;
            try {
                err_desc = "Failed to create input object";
                RopInput input = rop.create_input(new RopData(message), false);

                err_desc = "Failed to create output object";
                RopOutput output = rop.create_output("signed.asc");

                // initialize and configure sign operation, use op_sign_create(cleartext/detached)
                // for cleartext or detached signature
                err_desc = "Failed to create sign operation";
                sign = ses.op_sign_create(input, output);
            } catch(RopError ex) {
                System.out.println(err_desc);
                throw ex;
            }

            // armor, file name, compression
            sign.set_armor(true);
            sign.set_file_name("message.txt");
            sign.set_file_mtime(Instant.now());
            sign.set_compression("ZIP", 6);
            // signatures creation time - by default will be set to the current time as well
            sign.set_creation_time(Instant.now());
            // signatures expiration time - by default will be 0, i.e. never expire
            sign.set_expiration(Duration.ofDays(365));
            // set hash algorithm - should be compatible for all signatures
            sign.set_hash(RopBind.ALG_HASH_SHA256);

            try {
                // now add signatures. First locate the signing key, then add and setup signature
                // RSA signature
                err_desc = "Failed to locate signing key rsa@key.";
                RopKey key = ses.locate_key("userid", "rsa@key");
                Sign.key_ids[0] = key.keyid();
                Sign.key_fprints[0] = key.fprint();

                err_desc = "Failed to add signature for key rsa@key.";
                sign.add_signature(key);

                // EdDSA signature
                err_desc = "Failed to locate signing key 25519@key.";
                key = ses.locate_key("userid", "25519@key");
                Sign.key_ids[1] = key.keyid();
                Sign.key_fprints[1] = key.fprint();

                err_desc = "Failed to add signature for key 25519@key.";
                sign.add_signature(key);

                // finally do signing
                err_desc = "Failed to add signature for key 25519@key.";
                sign.execute();

                System.out.println("Signing succeeded. See file signed.asc.");
            } catch(RopError ex) {
                System.out.println(err_desc);
                throw ex;
            }
        } finally {
            rop.drop_from(alt);
        }
    }

    public void execute() throws RopError {
        RopBind rop = new RopBind();
        try {
            sign(rop);
        } finally {
            rop.Close();
        }
    }

    public static void main(String[] args) throws RopError {
        Sign sign = new Sign();
        sign.execute();
    }
}
