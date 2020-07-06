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

package tech.janky.jarop.tests;

import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Vector;

import tech.janky.jarop.RopError;
import tech.janky.jarop.examples.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.jupiter.api.AfterAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.commons.util.PreconditionViolationException;
import java.io.PrintWriter;


public class RopExamplesTest {
    private static Vector<String> test_key_ids;

    @BeforeAll
    static void setUp() throws RopError {
        for(String fname : new String[] {"pubring.pgp", "secring.pgp"}) {
            try {
                Files.delete(Paths.get(fname));
            } catch(IOException ex) {}
        }
        test_key_ids = new Vector<String>();
    }
    
    @AfterAll
    static void tearDown() {
        Vector<String> fnames = new Vector<String>();
        for(String name : new String[] {"pubring.pgp", "secring.pgp", "encrypted.asc", "signed.asc"})
            fnames.add(name);
        for(String keyid : test_key_ids) {
            fnames.add(String.format("key-%s-pub.asc", keyid));
            fnames.add(String.format("key-%s-sec.asc", keyid));
        }
        for(String fname : fnames) {
            try {
                Files.delete(Paths.get(fname));
            } catch(IOException ex) {}
        }
    }

    @Test
    void test_examples() throws RopError, Exception {
        //Execute
        (new Generate()).execute();
        (new Encrypt()).execute();
        (new Decrypt()).execute();
        if(Encrypt.message.compareTo(Decrypt.message) != 0)
            throw new Exception("Decryption Failed!");
        (new Sign()).execute();
        for(int idx = 0; idx < 2; idx++)
            test_key_ids.add(Sign.key_ids[idx]);
        (new Verify()).execute();
        String[] out = new String[] {null}; 
        (new Dump()).execute(new String[] {"Dump", "-j", "signed.asc"}, out);

        //Parse the dump
        JSONParser pjson = new JSONParser();
        JSONArray jso = null, ref_jso = null;
        try {
            jso = (JSONArray)pjson.parse(out[0]);
        } catch(ParseException ex) {
            assertTrue(false);
        }
        InputStream inp = this.getClass().getResourceAsStream("et_json.txt");
        String data = null;
        try {
            byte[] bdata = new byte[inp.available()];
            inp.read(bdata);
            data = new String(bdata);
        } catch(IOException ex) {
            assertTrue(false);
        }
        data.replaceAll("b2617b172b2ceae2a1ed72435fc1286cf91da4d0", Sign.key_fprints[0].toLowerCase());
        data.replaceAll("5fc1286cf91da4d0", Sign.key_ids[0].toLowerCase());
        data.replaceAll("f1768c67ec5a9ead3061c2befeee14c57b1a12d9", Sign.key_fprints[1].toLowerCase());
        data.replaceAll("feee14c57b1a12d9", Sign.key_ids[1].toLowerCase());
        try {
            ref_jso = (JSONArray)pjson.parse(out[0]);
        } catch(ParseException ex) {
            assertTrue(false);
        }

        // Compare the jsons
        right_cmp_json(jso, ref_jso);

        System.out.println("SUCCESS !");
    }
    
    private void right_cmp_json(Object json, Object ref_json) throws Exception {
        if(JSONArray.class.isInstance(ref_json))
            for(int idx = 0; idx < ((JSONArray)ref_json).size(); idx++) 
                right_cmp_json(((JSONArray)json).get(idx), ((JSONArray)ref_json).get(idx));
        else if(JSONObject.class.isInstance(ref_json)) {
            if(((JSONObject)ref_json).size() > 0)
                for(Object key : ((JSONObject)ref_json).keySet())
                    right_cmp_json(((JSONObject)json).get(key), ((JSONObject)ref_json).get(key));
        } else if(!json.equals(ref_json))
            throw new Exception(String.format("FAILED! (%s != %s)", json, ref_json));
    }
    
    public static void main(String[] args) throws Exception {
        Launcher juLaunch = null;
        try {
            juLaunch = LauncherFactory.create();
        } catch(PreconditionViolationException ex) {}
        if(juLaunch != null) {
            SummaryGeneratingListener juSum = new SummaryGeneratingListener();
            juLaunch.execute(LauncherDiscoveryRequestBuilder.request().selectors(DiscoverySelectors.selectClass(RopExamplesTest.class)).build(), juSum);
            juSum.getSummary().printTo(new PrintWriter(System.out, true));
        } else {
            RopExamplesTest.setUp();
            RopExamplesTest tex = new RopExamplesTest();
            tex.test_examples();
            RopExamplesTest.tearDown();
        }
    }
}
