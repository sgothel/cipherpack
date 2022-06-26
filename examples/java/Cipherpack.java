/**
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2022 Gothel Software e.K.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.cipherpack.CPFactory;
import org.cipherpack.CPUtils;
import org.cipherpack.CipherpackListener;
import org.cipherpack.CryptoConfig;
import org.cipherpack.PackHeader;
import org.jau.nio.ByteInStream;

public class Cipherpack {

    static void print_usage() {
        CPUtils.println(System.err, "Usage: pack [-epk <enc-pub-key>]+ -ssk <sign-sec-key> -sskp <sign-sec-key-passphrase> -in <input-source> -target_path <target-path-filename> "+
                        "-intention <string> -version <file-version-str> -version_parent <file-version-parent-str> -out <output-filename>");
        CPUtils.println(System.err, "Usage: unpack [-spk <sign-pub-key>]+ -dsk <dec-sec-key> -dskp <dec-sec-key-passphrase> -in <input-source> -out <output-filename>");
    }

    public static void main(final String[] args) throws InterruptedException {
        final int argc = args.length;
        for(int i=0; i< argc; i++) {
            final String arg = args[i];
            if( arg.equals("-cp_debug") && args.length > (i+1) ) {
                System.setProperty("cipherpack.debug", args[++i]);
            } else if( arg.equals("-cp_verbose") && args.length > (i+1) ) {
                System.setProperty("cipherpack.verbose", args[++i]);
            }
        }
        CPFactory.checkInitialized();

        CPUtils.println(System.err, "Cipherpack initialized!");
        CPUtils.println(System.err, "Cipherpack Native Version "+CPFactory.getNativeVersion()+" (API "+CPFactory.getNativeAPIVersion()+")");
        CPUtils.println(System.err, "Cipherpack Java Version "+CPFactory.getImplVersion()+" (API "+CPFactory.getAPIVersion()+")");

        CPUtils.fprintf_td(System.err, "Called with %d arguments: ", argc);
        for(int i=0; i<argc; i++) {
            CPUtils.fprintf_td(System.err, "%s ", args[i]);
        }
        CPUtils.fprintf_td(System.err, "\n");
        int argi = 0;

        if( 1 >= argc ) {
            print_usage();
            return;
        }
        final String command = args[++argi];

        if( command.equals( "pack" ) ) {
            final List<String> enc_pub_keys = new ArrayList<String>();
            String sign_sec_key_fname = new String();
            final ByteBuffer sign_sec_key_passphrase = null;
            String source_name = new String();
            String target_path = new String();
            String intention = new String();
            String payload_version = "0";
            String payload_version_parent = "0";
            String fname_output = new String();
            for(int i=argi; i + 1 < argc; ++i) {
                final String arg = args[i];

                if( arg.equals("-epk") ) {
                    enc_pub_keys.add( args[++i] );
                } else if( arg.equals("-ssk") ) {
                    sign_sec_key_fname = args[++i];
                } else if( arg.equals("-sskp") ) {
                    // FIXME
                    // sign_sec_key_passphrase = args[++i];
                } else if( arg.equals("-in") ) {
                    source_name = args[++i];
                } else if( arg.equals("-target_path") ) {
                    target_path = args[++i];
                } else if( arg.equals("-intention") ) {
                    intention = args[++i];
                } else if( arg.equals("-version") ) {
                    payload_version = args[++i];
                } else if( arg.equals("-version_parent") ) {
                    payload_version_parent = args[++i];
                } else if( arg.equals("-out") ) {
                    fname_output = args[++i];
                }
            }
            if( 0 == enc_pub_keys.size() ||
                sign_sec_key_fname.isEmpty() ||
                source_name.isEmpty() ||
                target_path.isEmpty() ||
                fname_output.isEmpty() )
            {
                CPUtils.fprintf_td(System.err, "Pack: Error: Arguments incomplete\n");
                print_usage();
                return;
            }

            final ByteInStream source = ByteInStream.create(source_name); // 20_s default
            final PackHeader ph = org.cipherpack.Cipherpack.encryptThenSign(
                                                CryptoConfig.getDefault(),
                                                enc_pub_keys, sign_sec_key_fname, sign_sec_key_passphrase,
                                                source,
                                                target_path, intention,
                                                payload_version, payload_version_parent,
                                                new CipherpackListener(), fname_output);

            CPUtils.fprintf_td(System.err, "Pack: Encrypted %s to %s\n", source_name, fname_output);
            CPUtils.fprintf_td(System.err, "Pack: %s\n", ph.toString(true, true));
            return;
        }
        if( command == "unpack") {
            final List<String> sign_pub_keys = new ArrayList<String>();
            String dec_sec_key_fname = new String();
            final ByteBuffer dec_sec_key_passphrase = null;
            String source_name = new String();
            String fname_output = new String();
            for(int i=argi; i + 1 < argc; ++i) {
                final String arg = args[i];

                if( arg.equals("-spk") ) {
                    sign_pub_keys.add( args[++i] );
                } else if( arg.equals("-dsk") ) {
                    dec_sec_key_fname = args[++i];
                } else if( arg.equals("-dskp") ) {
                    // FIXME
                    // dec_sec_key_passphrase = args[++i];
                } else if( arg.equals("-in") ) {
                    source_name = args[++i];
                } else if( arg.equals("-out") ) {
                    fname_output = args[++i];
                }
            }
            if( 0 == sign_pub_keys.size() ||
                dec_sec_key_fname.isEmpty() ||
                source_name.isEmpty() ||
                fname_output.isEmpty() )
            {
                CPUtils.fprintf_td(System.err, "Unpack: Error: Arguments incomplete\n");
                print_usage();
                return;
            }

            final ByteInStream source = ByteInStream.create(source_name); // 20_s default
            final PackHeader ph = org.cipherpack.Cipherpack.checkSignThenDecrypt(
                                        sign_pub_keys, dec_sec_key_fname, dec_sec_key_passphrase,
                                        source,
                                        new CipherpackListener(), fname_output);

            // dec_sec_key_passphrase.resize(0);
            CPUtils.fprintf_td(System.err, "Unpack: Decypted %s to %s\n", source_name, fname_output);
            CPUtils.fprintf_td(System.err, "Unpack: %s\n", ph.toString(true, true));
            return;
        }
        CPUtils.fprintf_td(System.err, "Pack: Error: Unknown command\n");
        print_usage();
        return;
    }

}
