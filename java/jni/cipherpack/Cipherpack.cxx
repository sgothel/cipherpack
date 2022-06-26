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

jobject Java_org_cipherpack_Cipherpack_encryptThenSignImpl1(JNIEnv *env, jclass jclazz,
        jobject jccfg, jobject jenc_pub_keys,
        jstring jsign_sec_key_fname, jobject jpassphrase,
        jobject jsource_feed,
        jstring jtarget_path, jstring jsubject,
        jstring jpayload_version,
        jstring jpayload_version_parent,
        jobject cpListener, jstring jdestination_fname)
{
    try {
        jau::jni::shared_ptr_ref<jau::io::ByteInStream> refSource(env, jsource_feed); // hold until done
        jau::jni::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done

        cipherpack::CryptoConfig ccfg = jcipherpack::to_CryptoConfig(env, jccfg);
        std::vector<std::string> enc_pub_keys = jau::jni::convert_jlist_string_to_vector(env, jenc_pub_keys);
        std::string sign_sec_key_fname = jau::jni::from_jstring_to_string(env, jsign_sec_key_fname);
        jau::io::secure_string passphrase = nullptr != jpassphrase ? jau::jni::from_jbytebuffer_to_sstring(env, jpassphrase) : jau::io::secure_string();
        std::string target_path = jau::jni::from_jstring_to_string(env, jtarget_path);
        std::string subject = jau::jni::from_jstring_to_string(env, jsubject);
        std::string payload_version = jau::jni::from_jstring_to_string(env, jpayload_version);
        std::string payload_version_parent = jau::jni::from_jstring_to_string(env, jpayload_version_parent);
        std::string destination_fname = nullptr != jdestination_fname ? jau::jni::from_jstring_to_string(env, jdestination_fname) : "";

        cipherpack::PackHeader ph = encryptThenSign(ccfg, enc_pub_keys, sign_sec_key_fname, passphrase, *refSource,
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
        jstring jdec_sec_key_fname, jobject jpassphrase,
        jobject jsource_feed,
        jobject cpListener, jstring jdestination_fname)
{
    try {
        jau::jni::shared_ptr_ref<jau::io::ByteInStream> refSource(env, jsource_feed); // hold until done
        jau::jni::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done

        std::vector<std::string> sign_pub_keys = jau::jni::convert_jlist_string_to_vector(env, jsign_pub_keys);
        std::string dec_sec_key_fname = jau::jni::from_jstring_to_string(env, jdec_sec_key_fname);
        jau::io::secure_string passphrase = nullptr != jpassphrase ? jau::jni::from_jbytebuffer_to_sstring(env, jpassphrase) : jau::io::secure_string();
        std::string destination_fname = nullptr != jdestination_fname ? jau::jni::from_jstring_to_string(env, jdestination_fname) : "";

        cipherpack::PackHeader ph = checkSignThenDecrypt(sign_pub_keys, dec_sec_key_fname, passphrase, *refSource,
                                                         refListener.shared_ptr(), destination_fname);

        jobject jph = jcipherpack::to_jPackHeader(env, ph);

        return jph;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}