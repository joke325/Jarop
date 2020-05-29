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

// Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/generate.c

import tech.janky.jarop.RopBind;
import tech.janky.jarop.RopData;
import tech.janky.jarop.RopSession;
import tech.janky.jarop.RopKey;
import tech.janky.jarop.RopInput;
import tech.janky.jarop.RopOutput;
import tech.janky.jarop.RopError;
import tech.janky.jarop.SessionPassCallBack;


public class Generate implements SessionPassCallBack {
    // RSA key JSON description. 31536000 = 1 year expiration, 15768000 = half year
    public final static String RSA_KEY_DESC =
        "{" +
            "'primary': {" +
                "'type': 'RSA'," +
                "'length': 2048," +
                "'userid': 'rsa@key'," +
                "'expiration': 31536000," +
                "'usage': ['sign']," +
                "'protection': {" +
                    "'cipher': 'AES256'," +
                    "'hash': 'SHA256'" +
                "}" +
            "}," +
            "'sub': {" +
                "'type': 'RSA'," +
                "'length': 2048," +
                "'expiration': 15768000," +
                "'usage': ['encrypt']," +
                "'protection': {" +
                    "'cipher': 'AES256'," +
                    "'hash': 'SHA256'" +
                "}" +
            "}" +
        "}";
    public final static String CURVE_25519_KEY_DESC = 
        "{" +
            "'primary': {" +
                "'type': 'EDDSA'," +
                "'userid': '25519@key'," +
                "'expiration': 0," +
                "'usage': ['sign']," +
                "'protection': {" +
                    "'cipher': 'AES256'," +
                    "'hash': 'SHA256'" +
                "}" +
            "}," +
            "'sub': {" +
                "'type': 'ECDH'," +
                "'curve': 'Curve25519'," +
                "'expiration': 15768000," +
                "'usage': ['encrypt']," +
                "'protection': {" +
                    "'cipher': 'AES256'," +
                    "'hash': 'SHA256'" +
                "}" +
            "}" +
        "}";

    /**
    * basic pass provider implementation, which always return 'password' for key protection.
    * You may ask for password via stdin, or choose password based on key properties, whatever else 
    */
    public SessionPassCallBack.Ret PassCallBack(RopSession ses, Object ctx, RopKey key, String pgpCtx, int bufLen) {
        if(pgpCtx.compareTo("protect") == 0)
            return new SessionPassCallBack.Ret(true, "password");
        return new SessionPassCallBack.Ret(false, null);
    }

    /**
    * This simple helper function just prints armored key, searched by userid, to stdout.
    */
    private void print_key(RopBind rop, RopSession ses, String uid, boolean secret) throws RopError {
        // you may search for the key via userid, keyid, fingerprint, grip
        RopKey key = ses.locate_key("userid", uid);
        // create in-memory output structure to later use buffer
        RopOutput keydata = rop.create_output(0);
        try {
            if(secret)
                key.export_secret(keydata, true, true);
            else
                key.export_public(keydata, true, true);
            // get key's contents from the output structure
            RopData buf = keydata.memory_get_buf(false);
            System.out.println(buf.getString());
        } finally {
            rop.drop(keydata);
        }
    }
    
    private void export_key(RopBind rop, RopSession ses, String uid, boolean secret) throws RopError {
        // you may search for the key via userid, keyid, fingerprint, grip
        RopKey key = ses.locate_key("userid", uid);
        // get key's id and build filename
        String filename = String.format("key-%s-%s.asc", key.keyid(), secret? "sec" : "pub"); 
        RopOutput keyfile = rop.create_output(filename);
        try {
            key.export(keyfile, !secret, secret, true, true);
        } finally {
            rop.drop(keyfile);
        }
    }

    // this example function generates RSA/RSA and Eddsa/X25519 keypairs
    private void generate_keys(RopBind rop) throws RopError {
        int alt = rop.tagging();
        try {
            // initialize
            RopSession ses = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG);

            try {
                // set password provider
                ses.set_pass_provider(this, null);
                // generate EDDSA/X25519 keypair
                RopData key_grips = ses.generate_key_json(new RopData(CURVE_25519_KEY_DESC));
                // generate RSA keypair
                key_grips = ses.generate_key_json(new RopData(RSA_KEY_DESC));
                System.out.println(String.format("Generated RSA key/subkey:\n%s\n", key_grips));
            } catch(RopError ex) {
                System.out.println("Failed to generate keys");
                throw ex;
            }

            RopOutput keyfile = null;
            try {
                // create file output object and save public keyring with generated keys, overwriting
                // previous file if any. You may use max_alloc here as well.
                keyfile = rop.create_output("pubring.pgp");
                ses.save_keys_public(RopBind.KEYSTORE_GPG, keyfile);
            } catch(RopError ex) {
                System.out.println("Failed to save pubring");
                throw ex;
            } finally {
                rop.drop(keyfile);
            }

            keyfile = null;
            try {
                // create file output object and save secret keyring with generated keys
                keyfile = rop.create_output("secring.pgp");
                ses.save_keys_secret(RopBind.KEYSTORE_GPG, keyfile);
            } catch(RopError ex) {
                System.out.println("Failed to save secring");
                throw ex;
            } finally {
                rop.drop(keyfile);
            }
        } finally {
            rop.drop(new Integer(alt));
        }
    }
    
    private void output_keys(RopBind rop) throws RopError {
        int alt = rop.tagging();
        try {
            // initialize
            RopSession ses = rop.create_session(RopBind.KEYSTORE_GPG, RopBind.KEYSTORE_GPG);

            RopInput keyfile = null;
            try {
                // load keyrings
                keyfile = rop.create_input("pubring.pgp");
                // actually, we may exclude the public  to not check key types
                ses.load_keys_public(RopBind.KEYSTORE_GPG, keyfile);
            } catch(RopError ex) {
                System.out.println("Failed to read pubring");
                throw ex;
            } finally {
                rop.drop(keyfile);
            }

            keyfile = null;
            try {
                keyfile = rop.create_input("secring.pgp");
                ses.load_keys_secret(RopBind.KEYSTORE_GPG, keyfile);
            } catch(RopError ex) {
                System.out.println("Failed to read secring");
                throw ex;
            } finally {
                rop.drop(keyfile);
            }

            try {
                // print armored keys to the stdout
                print_key(rop, ses, "rsa@key", false);
                print_key(rop, ses, "rsa@key", true);
                print_key(rop, ses, "25519@key", false);
                print_key(rop, ses, "25519@key", true);
            } catch(Exception ex) {
                System.out.println("Failed to print armored key(s)");
                throw ex;
            }

            try {
                // write armored keys to the files, named key-<keyid>-pub.asc/named key-<keyid>-sec.asc
                export_key(rop, ses, "rsa@key", false);
                export_key(rop, ses, "rsa@key", true);
                export_key(rop, ses, "25519@key", false);
                export_key(rop, ses, "25519@key", true);
            } catch(Exception ex) {
                System.out.println("Failed to write armored key(s) to file");
                throw ex;
            }
        } finally {
            rop.drop_from(alt);
        }
    }

    public void execute() throws RopError {
        RopBind rop = new RopBind();
        try {
            generate_keys(rop);
            output_keys(rop);
        } finally {
            rop.Close();
        }
    }

    public static void main(String[] args) throws RopError {
        Generate gen = new Generate();
        gen.execute();
    }
}
