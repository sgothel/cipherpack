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

package test.org.cipherpack;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cipherpack.CPFactory;
import org.cipherpack.Cipherpack;
import org.cipherpack.CipherpackListener;
import org.cipherpack.CryptoConfig;
import org.cipherpack.PackHeader;
import org.jau.fs.CopyOptions;
import org.jau.fs.FileStats;
import org.jau.fs.FileUtil;
import org.jau.fs.TraverseOptions;
import org.jau.io.ByteInStream;
import org.jau.io.ByteInStreamUtil;
import org.jau.io.ByteInStream_Feed;
import org.jau.io.ByteInStream_File;
import org.jau.io.ByteInStream_URL;
import org.jau.io.PrintUtil;
import org.jau.sys.Clock;
import org.jau.util.BasicTypes;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Test01CipherpackSingle extends data_test {
    static final boolean DEBUG = false;

    static final String plaintext_version = "0";
    static final String plaintext_version_parent = "0";

    static final int IDX_0B = 0;
    static final int IDX_1B = 1;
    static final int IDX_11kiB = 2;
    static final int IDX_xbuffersz = 3;
    static final int IDX_xbuffersz_minus_tag = 4;
    static final int IDX_xbuffersz_plus_tag = 5;
    static final int IDX_65MiB = 6;

    static List<String> fname_plaintext_lst = new ArrayList<String>();
    static List<String> fname_encrypted_lst = new ArrayList<String>();
    static List<String> fname_decrypted_lst = new ArrayList<String>();

    static boolean remove_file(final String name) {
            final File file = new File( name );
            try {
                if( file.exists() ) {
                    if( !file.delete() ) {
                        PrintUtil.println(System.err, "Remove.1: Failed deletion of existing file "+name);
                        return false;
                    }
                }
                return true;
            } catch (final Exception ex) {
                PrintUtil.println(System.err, "Remove.2: Failed deletion of existing file "+name+": "+ex.getMessage());
                ex.printStackTrace();
            }
            return false;
    }
    static void add_test_file(final String name, final long size) {
            Assert.assertTrue( remove_file(name) );
            Assert.assertTrue( remove_file(name+".enc") );
            Assert.assertTrue( remove_file(name+".enc.dec") );
            {
                final String one_line = "Hello World, this is a test and I like it. Exactly 100 characters long. 0123456780 abcdefghjklmnop..";
                final Charset charset = Charset.forName("ASCII");
                final byte[] one_line_bytes = one_line.getBytes(charset);

                final File file = new File( name );
                Assert.assertFalse( file.exists() );

                try( final OutputStream out = new FileOutputStream(file); ) {

                    long written=0;
                    for(; written+one_line_bytes.length <= size; written+=+one_line_bytes.length) {
                        out.write( one_line_bytes );
                    }
                    for(; size-written > 0; ++written ) {
                        out.write( (byte)'_' );
                    }
                } catch (final Exception ex) {
                    PrintUtil.println(System.err, "Write test file: Failed "+name+": "+ex.getMessage());
                    ex.printStackTrace();
                }
            }
            final FileStats stats = new FileStats(name);
            Assert.assertTrue( stats.is_file() );
            Assert.assertEquals( size, stats.size() );
            fname_plaintext_lst.add(name);
            fname_encrypted_lst.add(name+".enc");
            fname_decrypted_lst.add(name+".enc.dec");
    }

    static {
        CPFactory.checkInitialized();
        final int buffer_size = 16384;
        int i=0;

        // Zero size .. Single finish chunk of less than buffer_size including the 16 bytes TAG
        add_test_file("test_cipher_0"+(i++)+"_0B.bin", 0);

        // Zero size .. Single finish chunk of less than buffer_size including the 16 bytes TAG
        add_test_file("test_cipher_0"+(i++)+"_1B.bin", 1);

        // Single finish chunk of less than buffer_size including the 16 bytes TAG
        add_test_file("test_cipher_0"+(i++)+"_11kiB.bin", 1024*11+1);

        // Will end up in a finish chunk of just 16 bytes TAG
        final long xbuffersz = 4 * buffer_size;
        add_test_file("test_cipher_0"+(i++)+"_xbuffsz_"+(xbuffersz/1024)+"kiB.bin", xbuffersz);

        // Will end up in a finish chunk of buffer_size including the 16 bytes TAG
        final long xbuffersz_minus = 4 * buffer_size - 16;
        add_test_file("test_cipher_0"+(i++)+"_xbuffsz_"+(xbuffersz/1024)+"kiB_sub16.bin", xbuffersz_minus);

        // Will end up in a finish chunk of 1 byte + 16 bytes TAG
        final long xbuffersz_plus = 4 * buffer_size + 1;
        add_test_file("test_cipher_0"+(i++)+"_xbuffsz_"+(xbuffersz/1024)+"kiB_add1.bin", xbuffersz_plus);

        // 65MB big file: Will end up in a finish chunk of 1 byte + 16 bytes TAG, 4160 chunks @ 16384
        add_test_file("test_cipher_0"+(i++)+"_65MiB.bin", 1024*1024*65+1);
    }

    static boolean system(final String[] command) {
        Process proc = null;
        try{
            proc = Runtime.getRuntime().exec(command);
            proc.waitFor();
            return true;
        }
        catch(final Exception ex)
        {
            if(proc!=null) {
                proc.destroy();
            }
            ex.printStackTrace();
        }
        return false;
    }

    static final String mini_httpd_exe() {
        final String os_name = System.getProperty("os.name");
        if( "FreeBSD".equals(os_name) ) {
            return "/usr/local/sbin/mini_httpd";
        } else {
            return "/usr/sbin/mini_httpd";
        }
    }

    @AfterClass
    public static void httpd_stop() {
        if( org.jau.io.UriTk.protocol_supported("http:") ) {
            Assert.assertTrue( system(new String[]{"killall", "mini_httpd"}) );
        }
    }

    static void httpd_start() {
        if( org.jau.io.UriTk.protocol_supported("http:") ) {
            Assert.assertTrue( system(new String[]{"killall", "mini_httpd"}) );
            final Path path = Paths.get("");
            final String directoryName = path.toAbsolutePath().toString();
            final String[] cmd = new String[]{mini_httpd_exe(), "-p", "8080", "-l", directoryName+"/mini_httpd.log"};
            PrintUtil.fprintf_td(System.err, "%s\n", Arrays.toString(cmd));
            Assert.assertTrue( system(cmd) );
        }
    }

    public static void hash_retest(final String hashAlgo,
                                   final String origFile, final byte[] hashValue_p1,
                                   final String hashedDescryptedFile, final byte[] hashValue_p2)
    {
        Assert.assertArrayEquals(hashValue_p1, hashValue_p2);

        final String suffix = Cipherpack.HashUtil.fileSuffix(hashAlgo);
        final String outFile = hashedDescryptedFile + "." + suffix;
        FileUtil.remove(outFile, TraverseOptions.none);

        Assert.assertTrue( Cipherpack.HashUtil.appendToFile(outFile, hashedDescryptedFile, hashAlgo, hashValue_p2) );

        final ByteInStream origIn = ByteInStreamUtil.to_ByteInStream(origFile);
        Assert.assertNotNull( origIn );
        final Instant t0 = Clock.getMonotonicTime();
        final byte[] origHashValue = Cipherpack.HashUtil.calc(hashAlgo, origIn);
        Assert.assertNotNull( origHashValue );
        Assert.assertArrayEquals(hashValue_p2, origHashValue);

        final Instant t1 = Clock.getMonotonicTime();
        final long td_ms = t0.until(t1, ChronoUnit.MILLIS);
        ByteInStreamUtil.print_stats("Hash '"+hashAlgo+"'", origIn.content_size(), td_ms);
        PrintUtil.fprintf_td(System.err, "\n");
    }

    public static void hash_retest(final String hashAlgo,
                                   final String origFile,
                                   final String hashedDescryptedFile, final byte[] hashValue_p2)
    {
        final String suffix = Cipherpack.HashUtil.fileSuffix(hashAlgo);
        final String outFile = hashedDescryptedFile + "." + suffix;
        FileUtil.remove(outFile, TraverseOptions.none);

        Assert.assertTrue( Cipherpack.HashUtil.appendToFile(outFile, hashedDescryptedFile, hashAlgo, hashValue_p2) );

        final ByteInStream origIn = ByteInStreamUtil.to_ByteInStream(origFile);
        Assert.assertNotNull( origIn );
        final Instant t0 = Clock.getMonotonicTime();
        final byte[] origHashValue = Cipherpack.HashUtil.calc(hashAlgo, origIn);
        Assert.assertNotNull( origHashValue );
        Assert.assertArrayEquals(hashValue_p2, origHashValue);

        final Instant t1 = Clock.getMonotonicTime();
        final long td_ms = t0.until(t1, ChronoUnit.MILLIS);
        ByteInStreamUtil.print_stats("Hash '"+hashAlgo+"'", origIn.content_size(), td_ms);
        PrintUtil.fprintf_td(System.err, "\n");
    }

    CipherpackListener silentListener = new CipherpackListener();

    @Test(timeout = 120000)
    public final void test00_enc_dec_file_single() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final int file_idx = IDX_11kiB;
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test00.enc");
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test00.dec");
            final String _path = fname_plaintext_lst.get(file_idx); // 'test_cipher_02_11kiB.bin'
            PrintUtil.fprintf_td(System.err, "test00_enc_dec_file_single(: path '%s', len %d\n", _path, _path.length());
            final ByteInStream_File source = new ByteInStream_File(_path);
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test00_enc_dec_file_single", plaintext_version, plaintext_version_parent,
                                                              enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test00_enc_dec_file_single: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test00_enc_dec_file_single: %s\n", ph1.toString(true, true));
            Assert.assertTrue( ph1.isValid() );
            enc_listener.check_counter_end();

            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, ph1.plaintext_hash_algo, fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test00_enc_dec_file_single: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test00_enc_dec_file_single: %s\n", ph2.toString(true, true));
            Assert.assertTrue( ph2.isValid() );
            dec_listener.check_counter_end();
        }
    }

    public static void main(final String args[]) {
        org.junit.runner.JUnitCore.main(Test01CipherpackSingle.class.getName());
    }
}
