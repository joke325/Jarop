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
class RopErr {
    //Error codes definitions

    private final static int rnp_success = 0x00000000;
    private final static int rnp_error_generic = 0x10000000;
    private final static int rnp_error_access = 0x11000000;
    private final static int rnp_error_bad_state = 0x12000000;
    private final static int rnp_error_not_enough_data = 0x13000000;

    // Common error codes
    
    public final static int RNP_SUCCESS = rnp_success;

    public final static int RNP_ERROR_GENERIC = rnp_error_generic;
    public final static int RNP_ERROR_BAD_FORMAT = rnp_error_generic+1;
    public final static int RNP_ERROR_BAD_PARAMETERS = rnp_error_generic+2;
    public final static int RNP_ERROR_NOT_IMPLEMENTED = rnp_error_generic+3;
    public final static int RNP_ERROR_NOT_SUPPORTED = rnp_error_generic+4;
    public final static int RNP_ERROR_OUT_OF_MEMORY = rnp_error_generic+5;
    public final static int RNP_ERROR_SHORT_BUFFER = rnp_error_generic+6;
    public final static int RNP_ERROR_NULL_POINTER = rnp_error_generic+7;

    // Storage
    
    public final static int RNP_ERROR_ACCESS = rnp_error_access;
    public final static int RNP_ERROR_READ = rnp_error_access+1;
    public final static int RNP_ERROR_WRITE = rnp_error_access+2;

    // Crypto
    
    public final static int RNP_ERROR_BAD_STATE = rnp_error_bad_state;
    public final static int RNP_ERROR_MAC_INVALID = rnp_error_bad_state+1;
    public final static int RNP_ERROR_SIGNATURE_INVALID = rnp_error_bad_state+2;
    public final static int RNP_ERROR_KEY_GENERATION = rnp_error_bad_state+3;
    public final static int RNP_ERROR_BAD_PASSWORD = rnp_error_bad_state+4;
    public final static int RNP_ERROR_KEY_NOT_FOUND = rnp_error_bad_state+5;
    public final static int RNP_ERROR_NO_SUITABLE_KEY = rnp_error_bad_state+6;
    public final static int RNP_ERROR_DECRYPT_FAILED = rnp_error_bad_state+7;
    public final static int RNP_ERROR_RNG = rnp_error_bad_state+8;
    public final static int RNP_ERROR_SIGNING_FAILED = rnp_error_bad_state+9;
    public final static int RNP_ERROR_NO_SIGNATURES_FOUND = rnp_error_bad_state+10;
    
    public final static int RNP_ERROR_SIGNATURE_EXPIRED = rnp_error_bad_state+11;

    // Parsing
    
    public final static int RNP_ERROR_NOT_ENOUGH_DATA = rnp_error_not_enough_data;
    public final static int RNP_ERROR_UNKNOWN_TAG = rnp_error_not_enough_data+1;
    public final static int RNP_ERROR_PACKET_NOT_CONSUMED = rnp_error_not_enough_data+2;
    public final static int RNP_ERROR_NO_USERID = rnp_error_not_enough_data+3;
    public final static int RNP_ERROR_EOF = rnp_error_not_enough_data+4;
}

public final class ROPE extends RopErr {
}
