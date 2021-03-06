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
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.plaf.basic.BasicGraphicsUtils;

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
public class Test01Cipherpack extends data_test {
    static final boolean DEBUG = false;

    static final String plaintext_version = "0";
    static final String plaintext_version_parent = "0";

    static final int IDX_11kiB = 0;
    static final int IDX_65MiB = 1;
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

                try( OutputStream out = new FileOutputStream(file); ) {

                    for(long i=0; i < size; i+=one_line_bytes.length) {
                        out.write( one_line_bytes );
                    }
                    out.write( (byte)'X' ); // make it odd

                } catch (final Exception ex) {
                    PrintUtil.println(System.err, "Write test file: Failed "+name+": "+ex.getMessage());
                    ex.printStackTrace();
                }
            }
            fname_plaintext_lst.add(name);
            fname_encrypted_lst.add(name+".enc");
            fname_decrypted_lst.add(name+".enc.dec");
    }

    static {
        add_test_file("test_cipher_01_11kiB.bin", 1024*11);
        add_test_file("test_cipher_02_65MiB.bin", 1024*1024*65);
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

    CipherpackListener silentListener = new CipherpackListener();

    @Test(timeout = 20000)
    public final void test01_enc_dec_file_ok() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final int file_idx = IDX_11kiB;
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                              silentListener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true));
            Assert.assertTrue( ph1.isValid() );

            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true));
            Assert.assertTrue( ph2.isValid() );
        }
        {
            final int file_idx = IDX_11kiB;
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key2_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                              silentListener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true));
            Assert.assertTrue( ph1.isValid() );

            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true));
            Assert.assertTrue( ph2.isValid() );
        }
        {
            final int file_idx = IDX_65MiB;
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key3_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                              silentListener, "", fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph1.toString(true, true));
            Assert.assertTrue( ph1.isValid() );

            {
                final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       silentListener, "", fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true));
                Assert.assertTrue( ph2.isValid() );
            }
            {
                final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       silentListener, "SHA-256", fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true));
                Assert.assertTrue( ph2.isValid() );
                hash_retest(fname_plaintext_lst.get(file_idx), fname_decrypted_lst.get(file_idx), ph2.plaintext_hash_algo, ph2.plaintext_hash);
            }
            {
                final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       silentListener, "SHA-512", fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true));
                Assert.assertTrue( ph2.isValid() );
                hash_retest(fname_plaintext_lst.get(file_idx), fname_decrypted_lst.get(file_idx), ph2.plaintext_hash_algo, ph2.plaintext_hash);
            }
            {
                final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                       enc_stream,
                                                                       silentListener, "BLAKE2b(512)", fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test01_enc_dec_file_ok: %s\n", ph2.toString(true, true));
                Assert.assertTrue( ph2.isValid() );
                hash_retest(fname_plaintext_lst.get(file_idx), fname_decrypted_lst.get(file_idx), ph2.plaintext_hash_algo, ph2.plaintext_hash);
            }
        }
    }

    public static void hash_retest(final String origFile, final String hashedDescryptedFile,
                                   final String hashAlgo, final byte[] hashValue)
    {
        final String suffix = Cipherpack.HashUtil.fileSuffix(hashAlgo);
        final String outFile = hashedDescryptedFile + "." + suffix;
        FileUtil.remove(outFile, TraverseOptions.none);

        Assert.assertTrue( Cipherpack.HashUtil.appendToFile(outFile, hashedDescryptedFile, hashAlgo, hashValue) );

        final ByteInStream origIn = ByteInStreamUtil.to_ByteInStream(origFile);
        Assert.assertNotNull( origIn );
        final Instant t0 = Clock.getMonotonicTime();
        final byte[] origHashValue = Cipherpack.HashUtil.calc(hashAlgo, origIn);
        Assert.assertNotNull( origHashValue );
        Assert.assertArrayEquals(hashValue, origHashValue);

        final Instant t1 = Clock.getMonotonicTime();
        final long td_ms = t0.until(t1, ChronoUnit.MILLIS);
        ByteInStreamUtil.print_stats("Hash '"+hashAlgo+"'", origIn.content_size(), td_ms);
        PrintUtil.fprintf_td(System.err, "\n");
    }

    @Test(timeout = 20000)
    public final void test02_enc_dec_file_error() {
        CPFactory.checkInitialized();

        final int file_idx = IDX_11kiB;
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
        final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                          enc_pub_keys,
                                                          sign_sec_key1_fname, sign_sec_key_passphrase,
                                                          source,
                                                          fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                          silentListener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_error: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_error: %s\n", ph1.toString(true, true));
        Assert.assertTrue( ph1.isValid() );

        {
            // Error: Not encrypted for terminal key 4
            final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( ph2.isValid() );
        }
        {
            // Error: Not signed from host key 4
            final List<String> sign_pub_keys_nope = Arrays.asList(sign_pub_key4_fname);
            final ByteInStream_File enc_stream = new ByteInStream_File(fname_encrypted_lst.get(file_idx));
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test02_enc_dec_file_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( ph2.isValid() );
        }
    }

    @Test(timeout = 20000)
    public final void test11_dec_http_ok() {
        CPFactory.checkInitialized();
        if( !org.jau.io.UriTk.protocol_supported("http:") ) {
            PrintUtil.fprintf_td(System.err, "http not supported, abort\n");
            return;
        }
        httpd_start();

        final int file_idx = IDX_11kiB;
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
        final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                          enc_pub_keys,
                                                          sign_sec_key1_fname, sign_sec_key_passphrase,
                                                          source,
                                                          fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                          silentListener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test11_dec_http_ok: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test11_dec_http_ok: %s\n", ph1.toString(true, true));
        Assert.assertTrue( ph1.isValid() );

        final String uri_encrypted = url_input_root + fname_encrypted_lst.get(file_idx);
        final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";

        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test11_dec_http_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test11_dec_http_ok: %s\n", ph2.toString(true, true));
            Assert.assertTrue( ph2.isValid() );
        }
        {
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key2_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test11_dec_http_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test11_dec_http_ok: %s\n", ph2.toString(true, true));
            Assert.assertTrue( ph2.isValid() );
        }
        {
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key3_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test11_dec_http_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test11_dec_http_ok: %s\n", ph2.toString(true, true));
            Assert.assertTrue( ph2.isValid() );
        }
    }

    @Test(timeout = 20000)
    public final void test12_dec_http_ok() {
        CPFactory.checkInitialized();
        if( !org.jau.io.UriTk.protocol_supported("http:") ) {
            PrintUtil.fprintf_td(System.err, "http not supported, abort\n");
            return;
        }
        httpd_start();

        final int file_idx = IDX_65MiB;
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
        final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                          enc_pub_keys,
                                                          sign_sec_key1_fname, sign_sec_key_passphrase,
                                                          source,
                                                          fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                          silentListener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test12_dec_http_ok: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test12_dec_http_ok: %s\n", ph1.toString(true, true));
        Assert.assertTrue( ph1.isValid() );

        final String uri_encrypted = url_input_root + fname_encrypted_lst.get(file_idx);
        final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";

        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test12_dec_http_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test12_dec_http_ok: %s\n", ph2.toString(true, true));
            Assert.assertTrue( ph2.isValid() );
        }
    }

    @Test(timeout = 20000)
    public final void test13_dec_http_error() {
        CPFactory.checkInitialized();
        if( !org.jau.io.UriTk.protocol_supported("http:") ) {
            PrintUtil.fprintf_td(System.err, "http not supported, abort\n");
            return;
        }
        httpd_start();

        final int file_idx = IDX_11kiB;
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
        final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                          enc_pub_keys,
                                                          sign_sec_key1_fname, sign_sec_key_passphrase,
                                                          source,
                                                          fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                          silentListener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test13_dec_http_error: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
        PrintUtil.fprintf_td(System.err, "test13_dec_http_error: %s\n", ph1.toString(true, true));
        Assert.assertTrue( ph1.isValid() );

        final String uri_encrypted = url_input_root + fname_encrypted_lst.get(file_idx);
        final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";

        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            // Error: Not encrypted for terminal key 4
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key4_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test13_dec_http_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test13_dec_http_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( ph2.isValid() );
        }
        {
            // Error: Not signed from host key 4
            final List<String> sign_pub_keys_nope = Arrays.asList( sign_pub_key4_fname );
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys_nope, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test13_dec_http_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test13_dec_http_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( ph2.isValid() );
        }
        {
            // Error: URL file doesn't exist
            final String uri_encrypted_err = url_input_root + "doesnt_exists.enc";
            final ByteInStream_URL enc_stream = new ByteInStream_URL(uri_encrypted_err, io_timeout);
            final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                   enc_stream,
                                                                   silentListener, Cipherpack.default_hash_algo(), file_decrypted);
            PrintUtil.fprintf_td(System.err, "test13_dec_http_error: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test13_dec_http_error: %s\n", ph2.toString(true, true));
            Assert.assertFalse( ph2.isValid() );
        }
    }

    static Thread executeOffThread(final Runnable runobj, final String threadName, final boolean detach) {
        final Thread t = new Thread( runobj, threadName );
        t.setDaemon( detach );
        t.start();
        return t;
    }

    // throttled, no content size, interruptReader() via set_eof() will avoid timeout
    static void feed_source_00(final ByteInStream_Feed enc_feed) {
        // long xfer_total = 0;
        final File enc_stream = new File(enc_feed.id());
        Assert.assertTrue( enc_stream.exists() );

        InputStream in = null;
        try {
            in = new FileInputStream(enc_stream);
            while( in.available() > 0 ) {
                final byte[] buffer = new byte[1024]; // 1k
                final int count = in.read(buffer);
                if( 0 < count ) {
                    // xfer_total += count;
                    enc_feed.write(buffer, 0, count);
                    try { Thread.sleep( 16 ); } catch(final Throwable t) {}
                }
            }
        } catch (final Exception ex) {
            PrintUtil.println(System.err, "feed_source_00: "+ex.getMessage());
            ex.printStackTrace();
        } finally {
            try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
        }
        // probably set after transfering due to above sleep, which also ends when total size has been reached.
        enc_feed.set_eof( 1 /* SUCCESS */ );
    }

    // throttled, with content size
    static void feed_source_01(final ByteInStream_Feed enc_feed) {
        long xfer_total = 0;
        final File enc_stream = new File(enc_feed.id());
        Assert.assertTrue( enc_stream.exists() );
        final long file_size = enc_stream.length();
        enc_feed.set_content_size( file_size );

        InputStream in = null;
        try {
            in = new FileInputStream(enc_stream);
            while( xfer_total < file_size && in.available() > 0 ) {
                final byte[] buffer = new byte[1024]; // 1k
                final int count = in.read(buffer);
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed.write(buffer, 0, count);
                    try { Thread.sleep( 16 ); } catch(final Throwable t) {}
                }
            }
        } catch (final Exception ex) {
            PrintUtil.println(System.err, "feed_source_01: "+ex.getMessage());
            ex.printStackTrace();
        } finally {
            try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
        }
        // probably set after transfering due to above sleep, which also ends when total size has been reached.
        enc_feed.set_eof( xfer_total == file_size ? 1 /* SUCCESS */ : -1 /* FAILED */);
    }

    // full speed, with content size
    static void feed_source_10(final ByteInStream_Feed enc_feed) {
        long xfer_total = 0;
        final File enc_stream = new File(enc_feed.id());
        Assert.assertTrue( enc_stream.exists() );
        final long file_size = enc_stream.length();
        enc_feed.set_content_size( file_size );

        InputStream in = null;
        try {
            in = new FileInputStream(enc_stream);
            while( xfer_total < file_size && in.available() > 0 ) {
                final byte[] buffer = new byte[1024]; // 1k
                final int count = in.read(buffer);
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed.write(buffer, 0, count);
                }
            }
        } catch (final Exception ex) {
            PrintUtil.println(System.err, "feed_source_10: "+ex.getMessage());
            ex.printStackTrace();
        } finally {
            try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
        }
        // probably set after transfering due to above sleep, which also ends when total size has been reached.
        enc_feed.set_eof( xfer_total == file_size ? 1 /* SUCCESS */ : -1 /* FAILED */);
    }

    // full speed, no content size, interrupting @ 1024 bytes within our header
    static void feed_source_20(final ByteInStream_Feed enc_feed) {
        long xfer_total = 0;
        final File enc_stream = new File(enc_feed.id());
        Assert.assertTrue( enc_stream.exists() );
        final long file_size = enc_stream.length();
        enc_feed.set_content_size( file_size );

        InputStream in = null;
        try {
            in = new FileInputStream(enc_stream);
            while( xfer_total < file_size && in.available() > 0 ) {
                final byte[] buffer = new byte[1024]; // 1k
                final int count = in.read(buffer);
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed.write(buffer, 0, count);
                    if( xfer_total >= 1024 ) {
                        enc_feed.set_eof( -1 /* FAILED */ ); // calls data_feed->interruptReader();
                        return;
                    }
                }
            }
        } catch (final Exception ex) {
            PrintUtil.println(System.err, "feed_source_20: "+ex.getMessage());
            ex.printStackTrace();
        } finally {
            try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
        }
    }

    // full speed, with content size, interrupting 1/4 way
    static void feed_source_21(final ByteInStream_Feed enc_feed) {
        long xfer_total = 0;
        final File enc_stream = new File(enc_feed.id());
        Assert.assertTrue( enc_stream.exists() );
        final long file_size = enc_stream.length();
        enc_feed.set_content_size( file_size );

        InputStream in = null;
        try {
            in = new FileInputStream(enc_stream);
            while( xfer_total < file_size && in.available() > 0 ) {
                final byte[] buffer = new byte[1024]; // 1k
                final int count = in.read(buffer);
                if( 0 < count ) {
                    xfer_total += count;
                    enc_feed.write(buffer, 0, count);
                    if( xfer_total >= file_size/4 ) {
                        enc_feed.set_eof( -1 /* FAILED */ ); // calls data_feed->interruptReader();
                        return;
                    }
                }
            }
        } catch (final Exception ex) {
            PrintUtil.println(System.err, "feed_source_21: "+ex.getMessage());
            ex.printStackTrace();
        } finally {
            try { if( null != in ) { in.close(); } } catch (final IOException e) { e.printStackTrace(); }
        }
    }

    @Test(timeout = 20000)
    public final void test21_enc_dec_fed_ok() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final int file_idx = IDX_11kiB;
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                              silentListener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: %s\n", ph1.toString(true, true));
            Assert.assertTrue( ph1.isValid() );

            final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";
            {
                // throttled, no content size, interruptReader() via set_eof() will avoid timeout
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_source_00(enc_feed); }, "test21_enc_dec_fed_ok::feed_source_00", false /* detach */);

                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       silentListener, Cipherpack.default_hash_algo(), file_decrypted);
                try {
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }

                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true));
                Assert.assertTrue( ph2.isValid() );
            }
            {
                // throttled, with content size
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_source_01(enc_feed); }, "test21_enc_dec_fed_ok::feed_source_01", false /* detach */);

                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       silentListener, Cipherpack.default_hash_algo(), file_decrypted);
                try {
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }

                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true));
                Assert.assertTrue( ph2.isValid() );
            }
        }
        {
            final int file_idx = IDX_65MiB;
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                              silentListener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: %s\n", ph1.toString(true, true));
            Assert.assertTrue( ph1.isValid() );

            final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";
            {
                // full speed, with content size
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_source_10(enc_feed); }, "test21_enc_dec_fed_ok::feed_source_10", false /* detach */);

                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       silentListener, Cipherpack.default_hash_algo(), file_decrypted);
                try {
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }

                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true));
                Assert.assertTrue( ph2.isValid() );
            }
        }
    }

    @Test(timeout = 20000)
    public final void test22_enc_dec_fed_irq() {
        CPFactory.checkInitialized();
        final List<String> enc_pub_keys = Arrays.asList(enc_pub_key1_fname, enc_pub_key2_fname, enc_pub_key3_fname);
        final List<String> sign_pub_keys = Arrays.asList(sign_pub_key1_fname, sign_pub_key2_fname, sign_pub_key3_fname);
        {
            final int file_idx = IDX_65MiB;
            final ByteInStream_File source = new ByteInStream_File(fname_plaintext_lst.get(file_idx));
            final PackHeader ph1 = Cipherpack.encryptThenSign(CryptoConfig.getDefault(),
                                                              enc_pub_keys,
                                                              sign_sec_key1_fname, sign_sec_key_passphrase,
                                                              source,
                                                              fname_plaintext_lst.get(file_idx), "test_case", plaintext_version, plaintext_version_parent,
                                                              silentListener, Cipherpack.default_hash_algo(), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: Encrypted %s to %s\n", fname_plaintext_lst.get(file_idx), fname_encrypted_lst.get(file_idx));
            PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: %s\n", ph1.toString(true, true));
            Assert.assertTrue( ph1.isValid() );

            final String file_decrypted = fname_encrypted_lst.get(file_idx)+".dec";
            {
                // full speed, no content size, interrupting @ 1024 bytes within our header
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_source_20(enc_feed); }, "test22_enc_dec_fed_irq::feed_source_20", false /* detach */);

                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       silentListener, Cipherpack.default_hash_algo(), file_decrypted);
                try {
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }

                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true));
                Assert.assertFalse( ph2.isValid() );
            }
            {
                // full speed, with content size, interrupting 1/4 way
                final ByteInStream_Feed enc_feed = new ByteInStream_Feed(fname_encrypted_lst.get(file_idx), io_timeout);
                final Thread feeder_thread = executeOffThread( () -> { feed_source_21(enc_feed); }, "test22_enc_dec_fed_irq::feed_source_21", false /* detach */);

                final PackHeader ph2 = Cipherpack.checkSignThenDecrypt(sign_pub_keys, dec_sec_key1_fname, dec_sec_key_passphrase,
                                                                       enc_feed,
                                                                       silentListener, Cipherpack.default_hash_algo(), file_decrypted);
                try {
                    feeder_thread.join(1000);
                } catch (final InterruptedException e) { }

                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: Decypted %s to %s\n", fname_encrypted_lst.get(file_idx), fname_decrypted_lst.get(file_idx));
                PrintUtil.fprintf_td(System.err, "test21_enc_dec_fed_ok: %s\n", ph2.toString(true, true));
                Assert.assertFalse( ph2.isValid() );
            }
        }
    }

    final static String root = "test_data";
    // submodule location with jaulib directly hosted below main project
    final static String project_root2 = "../../../jaulib/test_data";

    @Test(timeout = 20000)
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
        org.junit.runner.JUnitCore.main(Test01Cipherpack.class.getName());
    }
}
