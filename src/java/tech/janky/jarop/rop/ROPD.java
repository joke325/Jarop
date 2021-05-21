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
* Definitions
* @version 0.14.0
* @since   0.2
*/
class RopLibDef {
    public final static int RNP_KEY_EXPORT_ARMORED = (1 << 0);
    public final static int RNP_KEY_EXPORT_PUBLIC = (1 << 1);
    public final static int RNP_KEY_EXPORT_SECRET = (1 << 2);
    public final static int RNP_KEY_EXPORT_SUBKEYS = (1 << 3);

    public final static int RNP_KEY_REMOVE_PUBLIC = (1 << 0);
    public final static int RNP_KEY_REMOVE_SECRET = (1 << 1);
    public final static int RNP_KEY_REMOVE_SUBKEYS = (1 << 2);

    public final static int RNP_KEY_UNLOAD_PUBLIC = (1 << 0);
    public final static int RNP_KEY_UNLOAD_SECRET = (1 << 1);

    // Flags for optional details to include in JSON.
    public final static int RNP_JSON_PUBLIC_MPIS = (1 << 0);
    public final static int RNP_JSON_SECRET_MPIS = (1 << 1);
    public final static int RNP_JSON_SIGNATURES = (1 << 2);
    public final static int RNP_JSON_SIGNATURE_MPIS = (1 << 3);

    // Flags to include additional data in packet dumping
    public final static int RNP_JSON_DUMP_MPI = (1 << 0);
    public final static int RNP_JSON_DUMP_RAW = (1 << 1);
    public final static int RNP_JSON_DUMP_GRIP = (1 << 2);
    
    public final static int RNP_DUMP_MPI = (1 << 0);
    public final static int RNP_DUMP_RAW = (1 << 1);
    public final static int RNP_DUMP_GRIP = (1 << 2);

    // Flags for the key loading/saving functions.
    public final static int RNP_LOAD_SAVE_PUBLIC_KEYS = (1 << 0);
    public final static int RNP_LOAD_SAVE_SECRET_KEYS = (1 << 1);
    public final static int RNP_LOAD_SAVE_PERMISSIVE = (1 << 8);
    public final static int RNP_LOAD_SAVE_SINGLE = (1 << 9);

    // Flags for output structure creation.
    public final static int RNP_OUTPUT_FILE_OVERWRITE = (1 << 0);
    public final static int RNP_OUTPUT_FILE_RANDOM = (1 << 1);

    // User id type
    public final static int RNP_USER_ID = 1;
    public final static int RNP_USER_ATTR = 2;

    // Algorithm Strings
    
    public final static String RNP_ALGNAME_PLAINTEXT = "PLAINTEXT";
    public final static String RNP_ALGNAME_RSA = "RSA";
    public final static String RNP_ALGNAME_ELGAMAL = "ELGAMAL";
    public final static String RNP_ALGNAME_DSA = "DSA";
    public final static String RNP_ALGNAME_ECDH = "ECDH";
    public final static String RNP_ALGNAME_ECDSA = "ECDSA";
    public final static String RNP_ALGNAME_EDDSA = "EDDSA";
    public final static String RNP_ALGNAME_IDEA = "IDEA";
    public final static String RNP_ALGNAME_TRIPLEDES = "TRIPLEDES";
    public final static String RNP_ALGNAME_CAST5 = "CAST5";
    public final static String RNP_ALGNAME_BLOWFISH = "BLOWFISH";
    public final static String RNP_ALGNAME_TWOFISH = "TWOFISH";
    public final static String RNP_ALGNAME_AES_128 = "AES128";
    public final static String RNP_ALGNAME_AES_192 = "AES192";
    public final static String RNP_ALGNAME_AES_256 = "AES256";
    public final static String RNP_ALGNAME_CAMELLIA_128 = "CAMELLIA128";
    public final static String RNP_ALGNAME_CAMELLIA_192 = "CAMELLIA192";
    public final static String RNP_ALGNAME_CAMELLIA_256 = "CAMELLIA256";
    public final static String RNP_ALGNAME_SM2 = "SM2";
    public final static String RNP_ALGNAME_SM3 = "SM3";
    public final static String RNP_ALGNAME_SM4 = "SM4";
    public final static String RNP_ALGNAME_MD5 = "MD5";
    public final static String RNP_ALGNAME_SHA1 = "SHA1";
    public final static String RNP_ALGNAME_SHA256 = "SHA256";
    public final static String RNP_ALGNAME_SHA384 = "SHA384";
    public final static String RNP_ALGNAME_SHA512 = "SHA512";
    public final static String RNP_ALGNAME_SHA224 = "SHA224";
    public final static String RNP_ALGNAME_SHA3_256 = "SHA3-256";
    public final static String RNP_ALGNAME_SHA3_512 = "SHA3-512";
    public final static String RNP_ALGNAME_RIPEMD160 = "RIPEMD160";
    public final static String RNP_ALGNAME_CRC24 = "CRC24";

    // SHA1 is not considered secured anymore and SHOULD NOT be used to create messages (as per
    // Appendix C of RFC 4880-bis-02). SHA2 MUST be implemented.
    // Let's pre-empt this by specifying SHA256 - gpg interoperates just fine with SHA256 - agc,
    // 20090522
    
    public final static String DEFAULT_HASH_ALG = RNP_ALGNAME_SHA256;

    // Default symmetric algorithm
    
    public final static String DEFAULT_SYMM_ALG = RNP_ALGNAME_AES_256;

    // Keystore format: GPG, KBX (pub), G10 (sec), GPG21 ( KBX for pub, G10 for sec)
    
    public final static String RNP_KEYSTORE_GPG = "GPG";
    public final static String RNP_KEYSTORE_KBX = "KBX";
    public final static String RNP_KEYSTORE_G10 = "G10";
    public final static String RNP_KEYSTORE_GPG21 = "GPG21";
}

public final class ROPD extends RopLibDef { }
