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

// Inspired by https://github.com/rnpgp/rnp/blob/master/src/examples/dump.c

import java.util.Vector;
import java.util.Arrays;
import java.nio.file.Paths;
import java.io.IOException;

import tech.janky.jarop.RopBind;
import tech.janky.jarop.RopData;
import tech.janky.jarop.RopInput;
import tech.janky.jarop.RopOutput;
import tech.janky.jarop.InputCallBack;
import tech.janky.jarop.OutputCallBack;
import tech.janky.jarop.RopError;


public class Dump implements InputCallBack, OutputCallBack {
    // stdin reader
    public byte[] ReadCallBack(Object ctx, long maxLen) {
        byte[] buf = new byte[(int)maxLen];
        int read = 0;
        try {
            read = System.in.read(buf);
        } catch(IOException ex) {}
        return read>0? Arrays.copyOf(buf, read) : null;
    }
    public void RCloseCallBack(Object ctx) { }
    
    // stdout writer
    public boolean WriteCallBack(Object ctx, RopData buf) {
        System.out.print(buf.getString());
        return true;
    }
    public void WCloseCallBack(Object ctx) {
        System.out.println("");
    }
    
    private void print_usage(String program_name) {
        System.err.print(String.format(
            "Program dumps PGP packets. \n\nUsage:\n" +
            "\t%s [-d|-h] [input.pgp]\n" +
            "\t  -d : indicates whether to print packet content. Data is represented as hex\n" +
            "\t  -m : dump mpi values\n" +
            "\t  -g : dump key fingerprints and grips\n" +
            "\t  -j : JSON output\n" +
            "\t  -h : prints help and exists\n",
            Paths.get(program_name).getFileName()));
    }

    public void execute(String[] argv, String[] json_out) throws RopError {
        String input_file = null;
        boolean raw = false;
        boolean mpi = false;
        boolean grip = false;
        boolean json = false;
        boolean help = (argv.length < 2);

        /* Parse command line options:
            -i input_file [mandatory]: specifies name of the file with PGP packets
            -d : indicates wether to dump whole packet content
            -m : dump mpi contents
            -g : dump key grips and fingerprints
            -j : JSON output
            -h : prints help and exists
        */
        Vector<String> opts = new Vector<String>(), args = new Vector<String>();
        for(int idx = 1; idx < argv.length; idx++)
            if(argv[idx].length() >= 2 && argv[idx].charAt(0) == '-' && "dmgjh".indexOf(argv[idx].charAt(1)) >= 0)
                opts.add(argv[idx]);
            else
                args.add(argv[idx]);
        for(String opt : opts) {
            if(opt.compareTo("-d") == 0)
                raw = true;
            else if(opt.compareTo("-m") == 0)
                mpi = true;
            else if(opt.compareTo("-g") == 0)
                grip = true;
            else if(opt.compareTo("-j") == 0)
                json = true;
            else if(opt.length() > 0)
                help = true;
        }
        if(!help) {
            if(args.size() > 0)
                input_file = args.elementAt(0);

            RopBind rop = new RopBind();
            try {
                RopInput input = null;
                RopOutput output = null;
                try {
                    if(input_file != null)
                        input = rop.create_input(input_file);
                    else
                        input = rop.create_input(this, null);
                } catch(RopError err) {
                    System.out.format("Failed to open source: error %x", err.getErrCode());
                    throw err;
                }

                if(!json) {
                    try {
                        output = rop.create_output(this, null);
                    } catch(RopError err) {
                        System.out.format("Failed to open stdout: error %x", err.getErrCode());
                        throw err;
                    }
                    input.dump_packets_to_output(output, mpi, raw, grip);
                } else {
                    String jsn = input.dump_packets_to_json(mpi, raw, grip).getString();
                    if(json_out == null) {
                        System.out.println(jsn);
                        System.out.println("");
                    } else
                        json_out[0] = jsn;
                }
            } catch(RopError err) {
                // Inform in case of error occured during parsing
                System.out.format("Operation failed [error code: %x]", err.getErrCode());
                throw err;
            } finally {
                rop.Close();;
            }
        } else {
            print_usage(argv[0]);
        }
    }

    public static void main(String[] args) throws RopError {
        Dump dump = new Dump();
        String[] newArgs = new String[args.length+1];
        newArgs[0] = dump.getClass().getSimpleName();
        System.arraycopy(args, 0, newArgs, 1, args.length);
        dump.execute(newArgs, null);
    }
}
