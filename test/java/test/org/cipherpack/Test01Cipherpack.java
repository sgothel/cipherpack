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
import org.jau.util.BasicTypes;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Test01Cipherpack extends data_test {
    static final boolean DEBUG = false;

    static final String plaintext_version = "0";
    static final String plaintext_version_parent = "0";

    static final int IDX_0B = 0;
    static final int IDX_1B = 1;
    static final int IDX_11kiB = 2;
    static final int IDX_xbuffersz = 3;
    static final int IDX_xbuffersz_minus_tag = 4;
    static final int IDX_xbuffersz_plus_tag = 5;
    static final int IDX_46MiB = 6;
    static final int IDX_65MiB = 7;

    static List<String> fname_plaintext_lst = new ArrayList<String>();
    static List<String> fname_encrypted_lst = new ArrayList<String>();
    static List<String> fname_decrypted_lst = new ArrayList<String>();

    static String single_test_name = null;

    static boolean remove_file(final String name) {
            final File file = new File( name );
            try {
                if( file.exists() ) {
                    if( !file.delete() ) {
                        PrintUtil.println(System.err, "Remove.1: Error: Failed deletion of existing file "+name);
                        return false;
                    }
                }
                return true;
            } catch (final Exception ex) {
                PrintUtil.println(System.err, "Remove.2: Error: Failed deletion of existing file "+name+": "+ex.getMessage());
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
                    PrintUtil.println(System.err, "Error: Write test file: Failed "+name+": "+ex.getMessage());
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

        // 46MB Bug 574: Plaintext size: 48,001,024, encrypted size 48,007,099
        add_test_file("test_cipher_0"+(i++)+"_46MiB.bin", 48001024);

        // 65MB big file: Will end up in a finish chunk of 1 byte + 16 bytes TAG, 4160 chunks @ 16384
        add_test_file("test_cipher_0"+(i++)+"_65MiB.bin", 48007099); // 1024*1024*65+1);
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
        final Instant t0 = org.jau.sys.Clock.getMonotonicTime();
        final byte[] origHashValue = Cipherpack.HashUtil.calc(hashAlgo, origIn);
        Assert.assertNotNull( origHashValue );
        Assert.assertArrayEquals(hashValue_p2, origHashValue);

        final Instant t1 = org.jau.sys.Clock.getMonotonicTime();
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
        final Instant t0 = org.jau.sys.Clock.getMonotonicTime();
        final byte[] origHashValue = Cipherpack.HashUtil.calc(hashAlgo, origIn);
        Assert.assertNotNull( origHashValue );
        Assert.assertArrayEquals(hashValue_p2, origHashValue);

        final Instant t1 = org.jau.sys.Clock.getMonotonicTime();
        final long td_ms = t0.until(t1, ChronoUnit.MILLIS);
        ByteInStreamUtil.print_stats("Hash '"+hashAlgo+"'", origIn.content_size(), td_ms);
        PrintUtil.fprintf_td(System.err, "\n");
    }

    @Before
    public final void testFilter() {
        if( null != single_test_name && !single_test_name.equals(getTestMethodName()) ) {
            System.err.println("++++ TestFilter: Disabled "+getFullTestName(" - "));
            Assume.assumeTrue(false);
        } else {
            System.err.println("++++ TestFilter: Enabled "+getFullTestName(" - "));
        }
    }

    @Test(timeout = 120000)
    public final void test00_enc_dec_file_single() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final int file_idx = IDX_11kiB;
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test00.enc", true /* send_content */);
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test00.dec", true /* send_content */);
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test00_enc_dec_file_single", plaintext_version, plaintext_version_parent,
                                                              enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test00_enc_dec_file_single: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test00_enc_dec_file_single: %s\n", ph1.toString(true, true));
            Assert.assertTrue( "test00_enc: "+ph1.toString(), ph1.isValid() );
            enc_listener.check_counter_end(source.content_size());

            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, ph1.plaintext_hash_algo, fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test00_enc_dec_file_single: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test00_enc_dec_file_single: %s\n", ph2.toString(true, true));
            Assert.assertTrue( "test00_dec: "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end(ph2.plaintext_size);
        }
    }

    @Test(timeout = 120000)
    public final void test01_enc_dec_all_files() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        for(int file_idx = 0; file_idx < fname_plaintext_lst.size(); ++file_idx) {
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test01.enc."+file_idx, true /* send_content */);
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test01_enc_dec_all_files", plaintext_version, plaintext_version_parent,
                                                              enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_all_files: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_all_files: %s\n", ph1.toString(true, true));
            Assert.assertTrue( "test01_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
            enc_listener.check_counter_end(source.content_size());

            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test01.dec."+file_idx, true /* send_content */);
            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, ph1.plaintext_hash_algo, fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_all_files: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_all_files: %s\n", ph2.toString(true, true));
            Assert.assertTrue( "test01_dec: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end(ph2.plaintext_size);
            hash_retest(ph1.plaintext_hash_algo,
                        fname_plaintext_lst.get(file_idx), ph1.plaintext_hash,
                        fname_decrypted_lst.get(file_idx), ph2.plaintext_hash);
        }
    }

    @Test(timeout = 120000)
    public final void test02_enc_dec_file_misc() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final int file_idx = IDX_11kiB;
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test02.enc.1."+file_idx);
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test02_enc_dec_file_misc", plaintext_version, plaintext_version_parent,
                                                              enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_misc: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_misc: %s\n", ph1.toString(true, true));
            Assert.assertTrue( "test02_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
            enc_listener.check_counter_end();

            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test02.dec.1."+file_idx);
            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, ph1.plaintext_hash_algo, fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_misc: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_misc: %s\n", ph2.toString(true, true));
            Assert.assertTrue( "test02_dec: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
        {
            final int file_idx = IDX_11kiB;
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test02.enc.1."+file_idx);
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key2_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test02_enc_dec_file_misc", plaintext_version, plaintext_version_parent,
                                                              enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_misc: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_misc: %s\n", ph1.toString(true, true));
            Assert.assertTrue( "test02_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
            enc_listener.check_counter_end();

            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test02.dec.1."+file_idx);
            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, Cipherpack.default_hash_algo(), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_misc: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_misc: %s\n", ph2.toString(true, true));
            Assert.assertTrue( "test02_dec: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
    }

    @Test(timeout = 120000)
    public final void test03_enc_dec_file_perf() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);

        {
            final int file_idx = IDX_65MiB;
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test03.enc."+file_idx);
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key3_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test03_enc_dec_file_perf", plaintext_version, plaintext_version_parent,
                                                              enc_listener, "", fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: %s\n", ph1.toString(true, true));
            Assert.assertTrue( "test03_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
            enc_listener.check_counter_end();

            {
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test03.dec.1."+file_idx);
                final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       dec_listener, "", fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: %s\n", ph2.toString(true, true));
                Assert.assertTrue( "test03_dec.1: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end();
            }
            {
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test03.dec.2."+file_idx);
                final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       dec_listener, "SHA-256", fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: %s\n", ph2.toString(true, true));
                Assert.assertTrue( "test03_dec.2: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end();
                hash_retest(ph2.plaintext_hash_algo,
                                fname_plaintext_lst.get(file_idx),
                                fname_decrypted_lst.get(file_idx), ph2.plaintext_hash);
            }
            {
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test03.dec.3."+file_idx);
                final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       dec_listener, "SHA-512", fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: %s\n", ph2.toString(true, true));
                Assert.assertTrue( "test03_dec.3: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end();
                hash_retest(ph2.plaintext_hash_algo,
                                fname_plaintext_lst.get(file_idx),
                                fname_decrypted_lst.get(file_idx), ph2.plaintext_hash);
            }
            {
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test03.dec.4."+file_idx);
                final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       dec_listener, "BLAKE2b(512)", fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test03_enc_dec_file_perf: %s\n", ph2.toString(true, true));
                Assert.assertTrue( "test03_dec.4: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end();
                hash_retest(ph2.plaintext_hash_algo,
                                fname_plaintext_lst.get(file_idx),
                                fname_decrypted_lst.get(file_idx), ph2.plaintext_hash);
            }
        }
    }

    @Test(timeout = 120000)
    public final void test04_enc_dec_file_error() {
        CPFactory.checkInitialized();

        final int file_idx = IDX_11kiB;
        final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test04.enc."+file_idx);
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
        final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                          enc_pub_keys,
                                                          sign_sec_key1_fname, sign_sec_key_passphrase,
                                                          source,
                                                          fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                          enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test04_enc_dec_file_error: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test04_enc_dec_file_error: %s\n", ph1.toString(true, true));
        Assert.assertTrue( "test04_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
        enc_listener.check_counter_end();

        {
            // Error: Not encrypted for terminal key 4
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test04.dec.e1."+file_idx);
            final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, Cipherpack.default_hash_algo(), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test04_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test04_enc_dec_file_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( "test04_dec.e1: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
        {
            // Error: Not signed from host key 4
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test04.dec.e2."+file_idx);
            final List<String> sign_pub_keys_nope = Arrays.asList(sign_pub_key4_fname);
            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, Cipherpack.default_hash_algo(), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test04_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test04_enc_dec_file_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( "test04_dec.e2: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
    }

    @Test(timeout = 120000)
    public final void test11_dec_http_all_files() {
        CPFactory.checkInitialized();
        if( !org.jau.io.UriTk.protocol_supported("http:") ) {
            PrintUtil.fprintf_td(System.err, "http not supported, abort\n");
            return;
        }
        httpd_start();

        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        for(int file_idx = 0; file_idx < fname_plaintext_lst.size(); ++file_idx) {
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test11.enc."+file_idx);
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test11_dec_http_all_files", plaintext_version, plaintext_version_parent,
                                                              enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test11_dec_http_all_files: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test11_dec_http_all_files: %s\n", ph1.toString(true, true));
            Assert.assertTrue( "test11_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
            enc_listener.check_counter_end();

            final String uri_encrypted = url_input_root + fname_encrypted_lst.get(file_idx);
            final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";

            final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
            {
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test11.dec."+file_idx);
                final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       dec_listener, Cipherpack.default_hash_algo(), file_decrypted);
                PrintUtil.fprintf_td(System.err, "test11_dec_http_all_files: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test11_dec_http_all_files: %s\n", ph2.toString(true, true));
                Assert.assertTrue( "test11_dec: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end();
            }
        }
    }

    @Test(timeout = 120000)
    public final void test12_dec_http_misc() {
        CPFactory.checkInitialized();
        if( !org.jau.io.UriTk.protocol_supported("http:") ) {
            PrintUtil.fprintf_td(System.err, "http not supported, abort\n");
            return;
        }
        httpd_start();

        final int file_idx = IDX_11kiB;
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test12.dec."+file_idx);
        final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
        final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                          enc_pub_keys,
                                                          sign_sec_key1_fname, sign_sec_key_passphrase,
                                                          source,
                                                          fname_plaintext_lst.get(file_idx), "test12_dec_http_misc", plaintext_version, plaintext_version_parent,
                                                          enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test12_dec_http_misc: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test12_dec_http_misc: %s\n", ph1.toString(true, true));
        Assert.assertTrue( "test12_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
        enc_listener.check_counter_end();

        final String uri_encrypted = url_input_root + fname_encrypted_lst.get(file_idx);
        final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";

        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test12.dec.1."+file_idx);
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test12_dec_http_misc: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test12_dec_http_misc: %s\n", ph2.toString(true, true));
            Assert.assertTrue( "test12_dec.1: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
        {
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test12.dec.2."+file_idx);
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test12_dec_http_misc: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test12_dec_http_misc: %s\n", ph2.toString(true, true));
            Assert.assertTrue( "test12_dec.2: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
        {
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test12.dec.3."+file_idx);
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test12_dec_http_misc: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test12_dec_http_misc: %s\n", ph2.toString(true, true));
            Assert.assertTrue( "test12_dec.3: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
    }

    @Test(timeout = 120000)
    public final void test13_dec_http_perf() {
        CPFactory.checkInitialized();
        if( !org.jau.io.UriTk.protocol_supported("http:") ) {
            PrintUtil.fprintf_td(System.err, "http not supported, abort\n");
            return;
        }
        httpd_start();

        final int file_idx = IDX_65MiB;
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test13.enc."+file_idx);
        final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
        final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                          enc_pub_keys,
                                                          sign_sec_key1_fname, sign_sec_key_passphrase,
                                                          source,
                                                          fname_plaintext_lst.get(file_idx), "test13_dec_http_perf", plaintext_version, plaintext_version_parent,
                                                          enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test13_dec_http_perf: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test13_dec_http_perf: %s\n", ph1.toString(true, true));
        Assert.assertTrue( "test13_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
        enc_listener.check_counter_end();

        final String uri_encrypted = url_input_root + fname_encrypted_lst.get(file_idx);
        final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";

        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test13.dec.1."+file_idx);
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, ph1.plaintext_hash_algo, file_decrypted);
            PrintUtil.fprintf_td(System.err, "test13_dec_http_perf: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test13_dec_http_perf: %s\n", ph2.toString(true, true));
            Assert.assertTrue( "test13_dec.1: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();

            hash_retest(ph1.plaintext_hash_algo,
                        fname_plaintext_lst.get(file_idx), ph1.plaintext_hash,
                        fname_decrypted_lst.get(file_idx), ph2.plaintext_hash);
        }
        {
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test13.dec.2."+file_idx);
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, "", file_decrypted);
            PrintUtil.fprintf_td(System.err, "test13_dec_http_perf: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test13_dec_http_perf: %s\n", ph2.toString(true, true));
            Assert.assertTrue( "test13_dec.2: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
    }

    @Test(timeout = 120000)
    public final void test14_dec_http_error() {
        CPFactory.checkInitialized();
        if( !org.jau.io.UriTk.protocol_supported("http:") ) {
            PrintUtil.fprintf_td(System.err, "http not supported, abort\n");
            return;
        }
        httpd_start();

        final int file_idx = IDX_11kiB;
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test14.enc."+file_idx);
        final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
        final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                          enc_pub_keys,
                                                          sign_sec_key1_fname, sign_sec_key_passphrase,
                                                          source,
                                                          fname_plaintext_lst.get(file_idx), "test14_dec_http_error", plaintext_version, plaintext_version_parent,
                                                          enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test14_dec_http_error: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test14_dec_http_error: %s\n", ph1.toString(true, true));
        Assert.assertTrue( "test14_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
        enc_listener.check_counter_end();

        final String uri_encrypted = url_input_root + fname_encrypted_lst.get(file_idx);
        final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";

        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            // Error: Not encrypted for terminal key 4
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test14.dec.e1."+file_idx);
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test14_dec_http_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test14_dec_http_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( "test14_dec.e1: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
        {
            // Error: Not signed from host key 4
            final List<String> sign_pub_keys_nope = Arrays.asList( sign_pub_key4_fname );
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test14.dec.e2."+file_idx);
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test14_dec_http_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test14_dec_http_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( "test14_dec.e2: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
        {
            // Error: URL file doesn't exist
            final String uri_encrypted_err = url_input_root + "doesnt_exists.enc";
            final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test14.dec.e3."+file_idx);
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted_err, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   dec_listener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test14_dec_http_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test14_dec_http_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( "test14_dec.e3: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
            dec_listener.check_counter_end();
        }
    }

    static final int slow_buffer_sz = 1024;
    static final long slow_delay_ms = 8;

    static Thread executeOffThread(final Runnable runobj, final String threadName, final boolean detach) {
        final Thread t = new Thread( runobj, threadName );
        t.setDaemon( detach );
        t.start();
        return t;
    }

    static interface FeederFunc {
        void feed(final ByteInStream_Feed enc_feed);
    };

    // throttled, no content size, interruptReader() via set_eof() will avoid timeout
    static FeederFunc feed_source_00_nosize_slow = new FeederFunc() {
        @Override
        public void feed(final ByteInStream_Feed enc_feed) {
            // long xfer_total = 0;
            final File enc_stream = new File(enc_feed.id());
            Assert.assertTrue( enc_stream.exists() );

            InputStream in = null;
            try {
                in = new FileInputStream(enc_stream);
                final byte[] buffer = new byte[slow_buffer_sz];
                while( in.available() > 0 ) {
                    final int count = in.read(buffer);
                    if( 0 < count ) {
                        // xfer_total += count;
                        if( enc_feed.write(buffer, 0, count) ) {
                            try { Thread.sleep( slow_delay_ms ); } catch(final Throwable t) {}
                        } else {
                            PrintUtil.println(System.err, "feed_source_00: Error: Failed to write "+count+" bytes to feed: "+enc_feed.toString());
                            break;
                        }
                    }
                }
            } catch (final Exception ex) {
                PrintUtil.println(System.err, "feed_source_00: Error: "+ex.getMessage());
                ex.printStackTrace();
            } finally {
                try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
            }
            // probably set after transfering due to above sleep, which also ends when total size has been reached.
            enc_feed.set_eof( enc_feed.fail() ? -1 /* FAILED */ : 1 /* SUCCESS */ );
        } };

    // throttled, with content size
    static FeederFunc feed_source_01_sized_slow = new FeederFunc() {
        @Override
        public void feed(final ByteInStream_Feed enc_feed) {
            long xfer_total = 0;
            final File enc_stream = new File(enc_feed.id());
            Assert.assertTrue( enc_stream.exists() );
            final long file_size = enc_stream.length();
            enc_feed.set_content_size( file_size );

            InputStream in = null;
            try {
                in = new FileInputStream(enc_stream);
                final byte[] buffer = new byte[slow_buffer_sz];
                while( xfer_total < file_size && in.available() > 0 ) {
                    final int count = in.read(buffer);
                    if( 0 < count ) {
                        xfer_total += count;
                        if( enc_feed.write(buffer, 0, count) ) {
                            try { Thread.sleep( slow_delay_ms ); } catch(final Throwable t) {}
                        } else {
                            PrintUtil.println(System.err, "feed_source_01: Error: Failed to write "+count+" bytes to feed: "+enc_feed.toString());
                            break;
                        }
                    }
                }
            } catch (final Exception ex) {
                PrintUtil.println(System.err, "feed_source_01: Error: "+ex.getMessage());
                ex.printStackTrace();
            } finally {
                try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
            }
            // probably set after transfering due to above sleep, which also ends when total size has been reached.
            enc_feed.set_eof( !enc_feed.fail() && xfer_total == file_size ? 1 /* SUCCESS */ : -1 /* FAILED */);
        } };

    // full speed, no content size
    static FeederFunc feed_source_10_nosize_fast = new FeederFunc() {
        @Override
        public void feed(final ByteInStream_Feed enc_feed) {
            // long xfer_total = 0;
            final File enc_stream = new File(enc_feed.id());
            Assert.assertTrue( enc_stream.exists() );

            InputStream in = null;
            try {
                in = new FileInputStream(enc_stream);
                final byte[] buffer = new byte[Cipherpack.buffer_size];
                while( in.available() > 0 ) {
                    final int count = in.read(buffer);
                    if( 0 < count ) {
                        // xfer_total += count;
                        if( !enc_feed.write(buffer, 0, count) ) {
                            PrintUtil.println(System.err, "feed_source_10: Error: Failed to write "+count+" bytes to feed: "+enc_feed.toString());
                            break;
                        }
                    }
                }
            } catch (final Exception ex) {
                PrintUtil.println(System.err, "feed_source_10: Error: "+ex.getMessage());
                ex.printStackTrace();
            } finally {
                try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
            }
            // probably set after transfering due to above sleep, which also ends when total size has been reached.
            enc_feed.set_eof( enc_feed.fail() ? -1 /* FAIL */ : 1 /* SUCCESS */ );
        } };

    // full speed, with content size
    static FeederFunc feed_source_11_sized_fast = new FeederFunc() {
        @Override
        public void feed(final ByteInStream_Feed enc_feed) {
            long xfer_total = 0;
            final File enc_stream = new File(enc_feed.id());
            Assert.assertTrue( enc_stream.exists() );
            final long file_size = enc_stream.length();
            enc_feed.set_content_size( file_size );

            InputStream in = null;
            try {
                in = new FileInputStream(enc_stream);
                final byte[] buffer = new byte[Cipherpack.buffer_size];
                while( xfer_total < file_size && in.available() > 0 ) {
                    final int count = in.read(buffer);
                    if( 0 < count ) {
                        xfer_total += count;
                        if( !enc_feed.write(buffer, 0, count) ) {
                            PrintUtil.println(System.err, "feed_source_11: Error: Failed to write "+count+" bytes to feed: "+enc_feed.toString());
                            break;
                        }
                    }
                }
            } catch (final Exception ex) {
                PrintUtil.println(System.err, "feed_source_10: Error: "+ex.getMessage());
                ex.printStackTrace();
            } finally {
                try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
            }
            // probably set after transfering due to above sleep, which also ends when total size has been reached.
            enc_feed.set_eof( !enc_feed.fail() && xfer_total == file_size ? 1 /* SUCCESS */ : -1 /* FAILED */);
        } };

    // full speed, with content size, implicit eof based on count
    static FeederFunc feed_source_12_sized_eof_fast = new FeederFunc() {
        @Override
        public void feed(final ByteInStream_Feed enc_feed) {
            long xfer_total = 0;
            final File enc_stream = new File(enc_feed.id());
            Assert.assertTrue( enc_stream.exists() );
            final long file_size = enc_stream.length();
            enc_feed.set_content_size( file_size );

            InputStream in = null;
            try {
                in = new FileInputStream(enc_stream);
                boolean in_eof = false; // we can't rely on in.available(), not supported at least on SMB input stream
                final byte[] buffer = new byte[Cipherpack.buffer_size];
                while( xfer_total < file_size && !in_eof ) {
                    final int count = in.read(buffer);
                    if( 0 < count ) {
                        xfer_total += count;
                        if( !enc_feed.write(buffer, 0, count) ) {
                            PrintUtil.println(System.err, "feed_source_12: Error: Failed to write "+count+" bytes to feed: "+enc_feed.toString());
                            break;
                        }
                    } else if( 0 > count ) {
                        in_eof = true;
                    }
                }
            } catch (final Exception ex) {
                PrintUtil.println(System.err, "feed_source_12: Error: "+ex.getMessage());
                ex.printStackTrace();
            } finally {
                try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
            }
            // probably set after transfering due to above sleep, which also ends when total size has been reached.
            enc_feed.set_eof( !enc_feed.fail() && xfer_total == file_size ? 1 /* SUCCESS */ : -1 /* FAILED */);
        } };

    // full speed, no content size, interrupting @ 1024 bytes within our header
    static void feed_source_20_nosize_irqed_1k(final ByteInStream_Feed enc_feed) {
        long xfer_total = 0;
        final File enc_stream = new File(enc_feed.id());
        Assert.assertTrue( enc_stream.exists() );
        final long file_size = enc_stream.length();
        enc_feed.set_content_size( file_size );

        InputStream in = null;
        try {
            in = new FileInputStream(enc_stream);
            final byte[] buffer = new byte[1024];
            while( xfer_total < file_size && in.available() > 0 ) {
                final int count = in.read(buffer);
                if( 0 < count ) {
                    xfer_total += count;
                    if( enc_feed.write(buffer, 0, count) ) {
                        if( xfer_total >= 1024 ) {
                            enc_feed.set_eof( -1 /* FAILED */ ); // calls data_feed->interruptReader();
                            return;
                        }
                    } else {
                        PrintUtil.println(System.err, "feed_source_20: Error: Failed to write "+count+" bytes to feed: "+enc_feed.toString());
                        break;
                    }
                }
            }
        } catch (final Exception ex) {
            PrintUtil.println(System.err, "feed_source_20: Error: "+ex.getMessage());
            ex.printStackTrace();
        } finally {
            try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
        }
    }

    // full speed, with content size, interrupting 1/4 way
    static void feed_source_21_sized_irqed_quarter(final ByteInStream_Feed enc_feed) {
        long xfer_total = 0;
        final File enc_stream = new File(enc_feed.id());
        Assert.assertTrue( enc_stream.exists() );
        final long file_size = enc_stream.length();
        enc_feed.set_content_size( file_size );

        InputStream in = null;
        try {
            in = new FileInputStream(enc_stream);
            final byte[] buffer = new byte[1024];
            while( xfer_total < file_size && in.available() > 0 ) {
                final int count = in.read(buffer);
                if( 0 < count ) {
                    xfer_total += count;
                    if( enc_feed.write(buffer, 0, count) ) {
                        if( xfer_total >= file_size/4 ) {
                            enc_feed.set_eof( -1 /* FAILED */ ); // calls data_feed->interruptReader();
                            return;
                        }
                    } else {
                        PrintUtil.println(System.err, "feed_source_21: Error: Failed to write "+count+" bytes to feed: "+enc_feed.toString());
                        break;
                    }
                }
            }
        } catch (final Exception ex) {
            PrintUtil.println(System.err, "feed_source_21: Error: "+ex.getMessage());
            ex.printStackTrace();
        } finally {
            try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
        }
    }

    @Test(timeout = 120000)
    public final void test31_fed_all_files() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        for(int file_idx = 0; file_idx < fname_plaintext_lst.size(); ++file_idx) {
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test31.enc."+file_idx);
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test31_fed_all_files", plaintext_version, plaintext_version_parent,
                                                              enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test31_fed_all_files: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test31_fed_all_files: %s\n", ph1.toString(true, true));
            Assert.assertTrue( "test31_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
            enc_listener.check_counter_end();

            final FeederFunc[] feed_funcs = { feed_source_00_nosize_slow, feed_source_01_sized_slow,
                                              feed_source_10_nosize_fast, feed_source_11_sized_fast,
                                              feed_source_12_sized_eof_fast };
            final String[] feed_funcs_suffix = { "nosize_slow", "sized_slow", "nosize_fast", "sized_fast", "sized_eof_fast" };
            for(int func_idx=0; func_idx < feed_funcs.length; ++func_idx) {
                final FeederFunc feed_func = feed_funcs[func_idx];
                if( ( IDX_46MiB == file_idx || IDX_65MiB == file_idx ) && ( func_idx == 0 || func_idx == 1 ) ) {
                    continue; // skip big file, too slow -> takes too long time to test
                }
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test31.dec."+file_idx+"."+func_idx);
                final String suffix = feed_funcs_suffix[func_idx];
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_func.feed(enc_feed); }, "test31_fed_all_files::"+suffix, false /* detach */);

                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       dec_listener, ph1.plaintext_hash_algo, fname_decrypted_lst.get(file_idx));
                try {
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }

                PrintUtil.fprintf_td(System.err, "test31_fed_all_files %s: Decypted %s to %s\n", suffix, fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test31_fed_all_files %s: %s\n", suffix, ph2.toString(true, true));
                Assert.assertTrue( "test31_dec: file_idx "+file_idx+", "+suffix+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end();

                hash_retest(ph1.plaintext_hash_algo,
                            fname_plaintext_lst.get(file_idx), ph1.plaintext_hash,
                            fname_decrypted_lst.get(file_idx), ph2.plaintext_hash);
            }
        }
    }

    static public class Bug574CipherpackListener extends CipherpackListener {
        /** Maximum notifyTransferProgress() is 10Hz, i.e. min_period is 1/10 = 100ms. This throttle is to avoid overloading the UI. */
        private static final int MIN_PROGRESS_PERIOD_MS = 10;
        private Instant t_last;
        private Instant t_last_progress;
        private final String name;
        public long clock_gettime_in_ms;
        public static enum GetTimeMethod {
            /**
             * Triggers Bug574:
             *
             * Clock.getMonotonicTime() causes a freeze coming from callback UpdateCipherpackListener.notifyProgress()
             * called by org.cipherpack.Cipherpack.checkSignThenDecrypt1(Native Method)
             */
            JAU_GET_MONOTONIC_TIME,
            /** OK */
            JAU_GET_MONOTONIC_CURRENT_MS,
            /** OK */
            SYSTEM_GET_CURRENT_MS
        };
        final GetTimeMethod get_time_method = GetTimeMethod.JAU_GET_MONOTONIC_TIME;

        public Bug574CipherpackListener(final String _name) {
            super();
            t_last = null;
            t_last_progress = null;
            name = _name;
            clock_gettime_in_ms = 0;
        }

        @Override
        public void notifyError(final boolean decrypt_mode, final PackHeader header, final String msg) {
            PrintUtil.fprintf_td(System.err, "%s: Notify Error: clock_gettime_in %d ms, %s, %s\n",
                    name, clock_gettime_in_ms, msg, header.toString());
        }

        @Override
        public boolean notifyHeader(final boolean decrypt_mode, final PackHeader header) {
            PrintUtil.fprintf_td(System.err, "%s: Notify Header: %s\n", name, header.toString());
            return true;
        }

        @Override
        public boolean notifyProgress(final boolean decrypt_mode, final long plaintext_size, final long bytes_processed) {
            final Instant t0;
            switch( get_time_method ) {
                case JAU_GET_MONOTONIC_TIME:
                    // FIXME: Clock.getMonotonicTime() causes a freeze coming from callback UpdateCipherpackListener.notifyProgress()
                    //        called by org.cipherpack.Cipherpack.checkSignThenDecrypt1(Native Method)
                    t0 = org.jau.sys.Clock.getMonotonicTime();
                    break;
                case JAU_GET_MONOTONIC_CURRENT_MS:
                    // OK
                    t0 = Instant.ofEpochMilli(org.jau.sys.Clock.currentTimeMillis());
                    break;
                case SYSTEM_GET_CURRENT_MS:
                default:
                    // OK
                    t0 = Instant.ofEpochMilli(System.currentTimeMillis());
                    break;
            }
            if( null != t_last ) {
                clock_gettime_in_ms = t_last.until(t0, ChronoUnit.MILLIS);
            }
            t_last = t0;

            if( null != t_last_progress ) {
                final long td_ms = t_last_progress.until(t0, ChronoUnit.MILLIS);
                if( td_ms < MIN_PROGRESS_PERIOD_MS && ( plaintext_size > bytes_processed || 0 >= plaintext_size ) ) {
                    return true;
                }
            }
            t_last_progress = t0;
            final double progress = plaintext_size > 0 ? (double) bytes_processed / (double) plaintext_size * 100.0 : -1.0;
            PrintUtil.fprintf_td(System.err, "%s: Notify Progress: %,d bytes received, %.02f%%\n", name, bytes_processed, progress);
            return true;
        }

        @Override
        public void notifyEnd(final boolean decrypt_mode, final PackHeader header) {
            PrintUtil.fprintf_td(System.err, "%s: Notify End: %s\n", name, header.toString());
        }
    };

    @Test(timeout = 120000)
    public final void test32_bug574() {
        CPFactory.checkInitialized();
        final String test_plaintext_file = System.getenv("PLAINTEXT_FILE");
        final String test_encrypted_file = System.getenv("ENCRYPTED_FILE");
        final String test_loops_s = System.getenv("TEST_LOOPS");
        int test_loops = 1;
        if( null != test_loops_s ) {
            try {
                test_loops = Integer.parseInt(test_loops_s);
            } catch(final Exception ex) {
                ex.printStackTrace();
            }
        }
        String fname_plaintext;
        String fname_encrypted;
        String fname_decrypted;
        if( null == test_plaintext_file ) {
            final int file_idx = IDX_46MiB; // IDX_65MiB;
            fname_plaintext = fname_plaintext_lst.get(file_idx);
            fname_encrypted = fname_encrypted_lst.get(file_idx);
            fname_decrypted = fname_decrypted_lst.get(file_idx);
        } else {
            fname_plaintext = test_plaintext_file;
            if( null == test_encrypted_file ) {
                fname_encrypted = test_plaintext_file+".enc";
            } else {
                fname_encrypted = test_encrypted_file;
            }
            fname_decrypted = test_plaintext_file+".enc.dec";
        }

        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname, enc_pub_key4_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);

        if( null == test_encrypted_file ) {
            // 46MB Bug 574: Plaintext size: 48,001,024, encrypted size 48,007,099
            // adding 1077 bytes to achieve encrypted size 48,007,099
            final String plaintext_version_bytes = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test32.enc");
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext);
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext, "test32_bug574", plaintext_version_bytes, plaintext_version_parent,
                                                              enc_listener, Cipherpack.default_hash_algo(), fname_encrypted);
            PrintUtil.fprintf_td(System.err, "test32_bug574: Encrypted %s to %s\n", fname_plaintext, fname_encrypted);
            PrintUtil.fprintf_td(System.err, "test32_bug574: %s\n", ph1.toString(true, true));
            Assert.assertTrue( "test32_bug574: "+ph1.toString(), ph1.isValid() );
            enc_listener.check_counter_end();
        }

        for(int loop_idx = 0; loop_idx < test_loops; ++loop_idx) {
            final String suffix = "sized_eof_fast_"+Integer.toString(loop_idx);
            final FeederFunc feed_func = feed_source_12_sized_eof_fast;
            final Bug574CipherpackListener dec_listener = new Bug574CipherpackListener(suffix);
            final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted, 5000); // 5_s only // io_timeout);
            final Thread feeder_thread = executeOffThread( () -> { feed_func.feed(enc_feed); }, "test32_bug574::"+suffix, false /* detach */);

            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_feed,
                                                                   dec_listener, "", fname_decrypted);
            try {
                feeder_thread.join(1000);
            } catch (final InterruptedException e) { }

            PrintUtil.fprintf_td(System.err, "test32_bug574 %s: Decypted %s to %s\n", suffix, fname_encrypted, fname_decrypted);
            PrintUtil.fprintf_td(System.err, "test32_bug574 %s: clock_gettime_in %d ms, %s\n",
                    suffix, dec_listener.clock_gettime_in_ms, ph2.toString(true, true));
            Assert.assertTrue( "Bug574: Hang within clock_gettime "+dec_listener.clock_gettime_in_ms+" ms, "+suffix, dec_listener.clock_gettime_in_ms < 10 );
            Assert.assertTrue( "test32_bug574: "+suffix+", "+ph2.toString(), ph2.isValid() );

            // hash_retest(ph1.plaintext_hash_algo,
            //             fname_plaintext_lst.get(file_idx), ph1.plaintext_hash,
            //             fname_decrypted_lst.get(file_idx), ph2.plaintext_hash);
        }
    }

    @Test(timeout = 120000)
    public final void test34_enc_dec_fed_irq() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final int file_idx = IDX_65MiB;
            final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test34.enc."+file_idx);
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test34_enc_dec_fed_irq", plaintext_version, plaintext_version_parent,
                                                              enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test34_enc_dec_fed_irq: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test34_enc_dec_fed_irq: %s\n", ph1.toString(true, true));
            Assert.assertTrue( "test34_enc: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
            enc_listener.check_counter_end();

            final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";
            {
                // full speed, no content size, interrupting @ 1024 bytes within our header
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test34.dec.e1."+file_idx);
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_source_20_nosize_irqed_1k(enc_feed); }, "test22_enc_dec_fed_irq::feed_source_20", false /* detach */);

                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       dec_listener, Cipherpack.default_hash_algo(), file_decrypted);
                try {
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }

                PrintUtil.fprintf_td(System.err, "test34_enc_dec_fed_irq: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test34_enc_dec_fed_irq: %s\n", ph2.toString(true, true));
                Assert.assertFalse( "test34_dec.e1: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end();
            }
            {
                // full speed, with content size, interrupting 1/4 way
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test34.dec.e2."+file_idx);
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_source_21_sized_irqed_quarter(enc_feed); }, "test22_enc_dec_fed_irq::feed_source_21", false /* detach */);

                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       dec_listener, Cipherpack.default_hash_algo(), file_decrypted);
                try {
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }

                PrintUtil.fprintf_td(System.err, "test34_enc_dec_fed_irq: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test34_enc_dec_fed_irq: %s\n", ph2.toString(true, true));
                Assert.assertFalse( "test34_dec.e2: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end();
            }
        }
    }

    @Test(timeout = 120000)
    public final void test41_abort_stream() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        for(int abort_item=1; abort_item<=3; ++abort_item) {
            final int file_idx = IDX_xbuffersz;
            PackHeader ph1;
            {
                final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test41.enc.1."+abort_item, true /* send_content */);
                enc_listener.set_abort(abort_item);
                final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
                ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                 enc_pub_keys,
                                                 sign_sec_key1_fname, sign_sec_key_passphrase,
                                                 source,
                                                 fname_plaintext_lst.get(file_idx), "test41_enc_1."+abort_item, plaintext_version, plaintext_version_parent,
                                                 enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_enc_1.%d: Encrypted %s to %s\n", abort_item, fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_enc_1.%d: %s\n", abort_item, ph1.toString(true, true));
                Assert.assertFalse( "test41_enc.1: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
                enc_listener.check_counter_end(0);
            }
            {
                final LoggingCipherpackListener enc_listener = new LoggingCipherpackListener("test41.enc.2."+abort_item, true /* send_content */);
                final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
                ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                 enc_pub_keys,
                                                 sign_sec_key1_fname, sign_sec_key_passphrase,
                                                 source,
                                                 fname_plaintext_lst.get(file_idx), "test41_enc_2."+abort_item, plaintext_version, plaintext_version_parent,
                                                 enc_listener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_enc_2.%d: Encrypted %s to %s\n", abort_item, fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_enc_2.%d: %s\n", abort_item, ph1.toString(true, true));
                Assert.assertTrue( "test41_enc.2: file_idx "+file_idx+", "+ph1.toString(), ph1.isValid() );
                enc_listener.check_counter_end(source.content_size());
            }
            {
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test41.dec.1"+abort_item, true /* send_content */);
                dec_listener.set_abort(abort_item);
                final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       dec_listener, ph1.plaintext_hash_algo, fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_dec.1.%d: Decypted %s to %s\n", abort_item, fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_dec.1.%d: %s\n", abort_item, ph2.toString(true, true));
                Assert.assertFalse( "test41_dec.1: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end(0);
            }
            if( !org.jau.io.UriTk.protocol_supported("http:") ) {
                PrintUtil.fprintf_td(System.err, "http not supported, abort\n");
            } else {
                httpd_start();
                final String uri_encrypted = url_input_root + fname_encrypted_lst.get(file_idx);
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test41.dec.2"+abort_item, true /* send_content */);
                dec_listener.set_abort(abort_item);
                final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       dec_listener, ph1.plaintext_hash_algo, fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_dec.2.%d: Decypted %s to %s\n", abort_item, fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_dec.2.%d: %s\n", abort_item, ph2.toString(true, true));
                Assert.assertFalse( "test41_dec.2: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end(0);
            }
            {
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test41.dec.3"+abort_item, true /* send_content */);
                dec_listener.set_abort(abort_item);
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_source_11_sized_fast.feed(enc_feed); }, "test41.dec.3."+abort_item, false /* detach */);
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       dec_listener, ph1.plaintext_hash_algo, fname_decrypted_lst.get(file_idx));
                try {
                    enc_feed.closeStream(); // ends feeder_thread loop
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }
                PrintUtil.fprintf_td(System.err, "test41_dec.3.%d: Decypted %s to %s\n", abort_item, fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_dec.3.%d: %s\n", abort_item, ph2.toString(true, true));
                Assert.assertFalse( "test41_dec.3: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end(0);
            }
            {
                final LoggingCipherpackListener dec_listener = new LoggingCipherpackListener("test41.dec.4"+abort_item, true /* send_content */);
                dec_listener.set_abort(abort_item);
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_source_10_nosize_fast.feed(enc_feed); }, "test41.dec.4."+abort_item, false /* detach */);
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       dec_listener, ph1.plaintext_hash_algo, fname_decrypted_lst.get(file_idx));
                try {
                    enc_feed.closeStream(); // ends feeder_thread loop
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }
                PrintUtil.fprintf_td(System.err, "test41_dec.4.%d: Decypted %s to %s\n", abort_item, fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test41_dec.4.%d: %s\n", abort_item, ph2.toString(true, true));
                Assert.assertFalse( "test41_dec.4: file_idx "+file_idx+", "+ph2.toString(), ph2.isValid() );
                dec_listener.check_counter_end(0);
            }
        }
    }

    final static String root = "test_data";
    // submodule location with jaulib directly hosted below main project
    final static String project_root2 = "../../../jaulib/test_data";

    @Test(timeout = 120000)
    public final void test50_copy_and_verify() {
        final String title = "test50_copy_and_verify";
        final String hash_file = title+".hash";

        PrintUtil.fprintf_td(System.err, "\n");
        PrintUtil.fprintf_td(System.err, "%s\n", title);

        FileUtil.remove(hash_file, TraverseOptions.none);

        final FileStats source_stats = new FileStats(project_root2);
        Assert.assertTrue( source_stats.exists() );
        Assert.assertTrue( source_stats.is_dir() );

        final long[] source_bytes_hashed = { 0 };
        final byte[] source_hash = Cipherpack.HashUtil.calc(Cipherpack.default_hash_algo(), source_stats.path(), source_bytes_hashed);
        Assert.assertNotNull( source_hash );
        Assert.assertTrue( Cipherpack.HashUtil.appendToFile(hash_file, source_stats.path(), Cipherpack.default_hash_algo(), source_hash));

        // copy folder
        final String dest = root+"_copy_verify_test50";
        {
            final CopyOptions copts = new CopyOptions();
            copts.set(CopyOptions.Bit.recursive);
            copts.set(CopyOptions.Bit.preserve_all);
            copts.set(CopyOptions.Bit.sync);
            copts.set(CopyOptions.Bit.verbose);

            FileUtil.remove(dest, TraverseOptions.recursive);
            Assert.assertTrue( true == FileUtil.copy(source_stats.path(), dest, copts) );
        }
        final FileStats dest_stats = new FileStats(dest);
        Assert.assertTrue( source_stats.exists() );
        Assert.assertTrue( source_stats.ok() );
        Assert.assertTrue( source_stats.is_dir() );

        final long[] dest_bytes_hashed = { 0 };
        final byte[] dest_hash = Cipherpack.HashUtil.calc(Cipherpack.default_hash_algo(), dest_stats.path(), dest_bytes_hashed);
        Assert.assertNotNull( dest_hash );
        Assert.assertTrue( Cipherpack.HashUtil.appendToFile(hash_file, dest_stats.path(), Cipherpack.default_hash_algo(), dest_hash));

        // actual validation of hash values, i.e. same content
        Assert.assertArrayEquals(source_hash, dest_hash);
        Assert.assertEquals( source_bytes_hashed[0], dest_bytes_hashed[0] );

        PrintUtil.fprintf_td(System.err, "%s: bytes %,d, '%s'\n", title, dest_bytes_hashed[0],
                BasicTypes.bytesHexString(dest_hash, 0, dest_hash.length, true /* lsbFirst */));

        Assert.assertTrue( FileUtil.remove(dest, TraverseOptions.recursive) );
    }

    public static void main(final String args[]) {
        if( args.length > 0 ) {
            System.err.println("Launching test: class "+Test01Cipherpack.class.getName()+", method "+args[0]);
            single_test_name = args[0];
            org.junit.runner.JUnitCore.main(Test01Cipherpack.class.getName());
        } else {
            org.junit.runner.JUnitCore.main(Test01Cipherpack.class.getName());
        }
    }
}
