/*
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

#include "org_cipherpack_Cipherpack.h"

// #define VERBOSE_ON 1
#include <jau/debug.hpp>

#include "cipherpack/cipherpack.hpp"

#include "CipherpackHelper.hpp"

using namespace cipherpack;
using namespace jau::fractions_i64_literals;

jobject Java_org_cipherpack_Cipherpack_encryptThenSignImpl1(JNIEnv *env, jclass jclazz,
        jobject jccfg, jobject jenc_pub_keys,
        jstring jsign_sec_key_fname, jstring jpassphrase,
        jobject jsource_feed,
        jstring jtarget_path, jstring jsubject,
        jstring jpayload_version,
        jstring jpayload_version_parent,
        jobject cpListener, jstring jdestination_fname)
{
    try {
        jau::shared_ptr_ref<jau::io::ByteInStream_Feed> refFeed(env, jsource_feed); // hold until done
        jau::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done

        CryptoConfig ccfg = jcipherpack::to_CryptoConfig(env, jccfg);
        std::vector<std::string> enc_pub_keys = jau::convert_jlist_string_to_vector(env, jenc_pub_keys);
        std::string sign_sec_key_fname = jau::from_jstring_to_string(env, jsign_sec_key_fname);
        std::string passphrase = jau::from_jstring_to_string(env, jpassphrase);
        std::string target_path = jau::from_jstring_to_string(env, jtarget_path);
        std::string subject = jau::from_jstring_to_string(env, jsubject);
        std::string payload_version = jau::from_jstring_to_string(env, jpayload_version);
        std::string payload_version_parent = jau::from_jstring_to_string(env, jpayload_version_parent);
        std::string destination_fname = nullptr != jdestination_fname ? jau::from_jstring_to_string(env, jdestination_fname) : "";

        PackHeader ph = encryptThenSign(ccfg, enc_pub_keys, sign_sec_key_fname, passphrase, *refFeed,
                                        target_path, subject, payload_version, payload_version_parent,
                                        refListener.shared_ptr(), destination_fname);

        jobject jph = jcipherpack::to_jPackHeader(env, ph);

        return jph;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}

jobject Java_org_cipherpack_Cipherpack_encryptThenSignImpl2(JNIEnv *env, jclass jclazz,
        jobject jccfg, jobject jenc_pub_keys,
        jstring jsign_sec_key_fname, jstring jpassphrase,
        jstring jsource_loc, jlong jsource_timeout_ms,
        jstring jtarget_path, jstring jsubject,
        jstring jpayload_version,
        jstring jpayload_version_parent,
        jobject cpListener, jstring jdestination_fname)
{
    try {
        jau::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done

        CryptoConfig ccfg = jcipherpack::to_CryptoConfig(env, jccfg);
        std::vector<std::string> enc_pub_keys = jau::convert_jlist_string_to_vector(env, jenc_pub_keys);
        std::string sign_sec_key_fname = jau::from_jstring_to_string(env, jsign_sec_key_fname);
        std::string passphrase = jau::from_jstring_to_string(env, jpassphrase);
        std::string source_loc = jau::from_jstring_to_string(env, jsource_loc);
        std::unique_ptr<jau::io::ByteInStream> source = jau::io::to_ByteInStream(source_loc, (int64_t)jsource_timeout_ms * 1_ms);
        std::string target_path = jau::from_jstring_to_string(env, jtarget_path);
        std::string subject = jau::from_jstring_to_string(env, jsubject);
        std::string payload_version = jau::from_jstring_to_string(env, jpayload_version);
        std::string payload_version_parent = jau::from_jstring_to_string(env, jpayload_version_parent);
        std::string destination_fname = nullptr != jdestination_fname ? jau::from_jstring_to_string(env, jdestination_fname) : "";

        PackHeader ph = encryptThenSign(ccfg, enc_pub_keys, sign_sec_key_fname, passphrase, *source,
                                        target_path, subject, payload_version, payload_version_parent,
                                        refListener.shared_ptr(), destination_fname);

        jobject jph = jcipherpack::to_jPackHeader(env, ph);

        return jph;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}


jobject Java_org_cipherpack_Cipherpack_checkSignThenDecrypt1(JNIEnv *env, jclass jclazz,
        jobject jsign_pub_keys,
        jstring jdec_sec_key_fname, jstring jpassphrase,
        jobject jsource_feed,
        jobject cpListener, jstring jdestination_fname)
{
    try {
        jau::shared_ptr_ref<jau::io::ByteInStream_Feed> refFeed(env, jsource_feed); // hold until done
        jau::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done

        std::vector<std::string> sign_pub_keys = jau::convert_jlist_string_to_vector(env, jsign_pub_keys);
        std::string dec_sec_key_fname = jau::from_jstring_to_string(env, jdec_sec_key_fname);
        std::string passphrase = jau::from_jstring_to_string(env, jpassphrase);
        std::string destination_fname = nullptr != jdestination_fname ? jau::from_jstring_to_string(env, jdestination_fname) : "";

        PackHeader ph = checkSignThenDecrypt(sign_pub_keys, dec_sec_key_fname, passphrase, *refFeed,
                                             refListener.shared_ptr(), destination_fname);

        jobject jph = jcipherpack::to_jPackHeader(env, ph);

        return jph;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}

jobject Java_org_cipherpack_Cipherpack_checkSignThenDecrypt2(JNIEnv *env, jclass jclazz,
        jobject jsign_pub_keys,
        jstring jdec_sec_key_fname, jstring jpassphrase,
        jstring jsource_loc, jlong jsource_timeout_ms,
        jobject cpListener, jstring jdestination_fname)
{
    try {
        jau::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done

        std::vector<std::string> sign_pub_keys = jau::convert_jlist_string_to_vector(env, jsign_pub_keys);
        std::string dec_sec_key_fname = jau::from_jstring_to_string(env, jdec_sec_key_fname);
        std::string passphrase = jau::from_jstring_to_string(env, jpassphrase);
        std::string source_loc = jau::from_jstring_to_string(env, jsource_loc);
        std::unique_ptr<jau::io::ByteInStream> source = jau::io::to_ByteInStream(source_loc, (int64_t)jsource_timeout_ms * 1_ms);
        std::string destination_fname = nullptr != jdestination_fname ? jau::from_jstring_to_string(env, jdestination_fname) : "";

        PackHeader ph = checkSignThenDecrypt(sign_pub_keys, dec_sec_key_fname, passphrase, *source,
                                             refListener.shared_ptr(), destination_fname);

        jobject jph = jcipherpack::to_jPackHeader(env, ph);

        return jph;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}

