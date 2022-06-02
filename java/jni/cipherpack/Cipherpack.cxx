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

/**
    private native PackHeader encryptThenSignImpl1(final CryptoConfig crypto_cfg,
                                                   final String[] enc_pub_keys,
                                                   final String sign_sec_key_fname, final String passphrase,
                                                   final ByteInStream_Feed source,
                                                   final String target_path, final String intention,
                                                   final String payload_version,
                                                   final String payload_version_parent,
                                                   final String destination_fname, final boolean overwrite,
                                                   final CipherpackListener listener);
 */
jobject Java_org_cipherpack_Cipherpack_encryptThenSignImpl1(JNIEnv *env, jclass jclazz,
        jobject jccfg, jobjectArray jenc_pub_keys,
        jstring jsign_sec_key_fname, jstring jpassphrase,
        jobject jsource_feed,
        jstring jtarget_path, jstring jintention,
        jstring jpayload_version,
        jstring jpayload_version_parent,
        jstring jdestination_fname, jboolean joverwrite,
        jobject cpListener)
{
    try {
        jau::shared_ptr_ref<jau::io::ByteInStream_Feed> refFeed(env, jsource_feed); // hold until done
        jau::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done
        CryptoConfig ccfg = jcipherpack::to_CryptoConfig(env, jccfg);

        const size_t enc_pub_keys_size = env->GetArrayLength(jenc_pub_keys);
        if( 0 >= enc_pub_keys_size ) {
            throw jau::IllegalArgumentException("enc_pub_keys array size "+std::to_string(enc_pub_keys_size)+" <= 0", E_FILE_LINE);
        }
        jau::JNICriticalArray<jobject, jobjectArray> criticalArray(env); // RAII - release
        jobject * enc_pub_keys_ptr = criticalArray.get(jenc_pub_keys, criticalArray.Mode::NO_UPDATE_AND_RELEASE);
        if( NULL == enc_pub_keys_ptr ) {
            throw jau::InternalError("GetPrimitiveArrayCritical(address enc_pub_keys array) is null", E_FILE_LINE);
        }
        std::vector<std::string> enc_pub_keys;
        for(size_t i=0; i<enc_pub_keys_size; ++i) {
            std::string enc_pub_key = jau::from_jstring_to_string(env, (jstring)enc_pub_keys_ptr[i]);
            enc_pub_keys.push_back(enc_pub_key);
        }

        std::string sign_sec_key_fname = jau::from_jstring_to_string(env, jsign_sec_key_fname);
        std::string passphrase = jau::from_jstring_to_string(env, jpassphrase);
        std::string target_path = jau::from_jstring_to_string(env, jtarget_path);
        std::string intention = jau::from_jstring_to_string(env, jintention);
        std::string payload_version = jau::from_jstring_to_string(env, jpayload_version);
        std::string payload_version_parent = jau::from_jstring_to_string(env, jpayload_version_parent);
        std::string destination_fname = jau::from_jstring_to_string(env, jdestination_fname);

        PackHeader ph = encryptThenSign(ccfg, enc_pub_keys, sign_sec_key_fname, passphrase, *refFeed,
                                        target_path, intention, payload_version, payload_version_parent, refListener.shared_ptr());

        jobject jph = jcipherpack::to_jPackHeader(env, ph);

        return jph;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}

/**
    private native PackHeader encryptThenSignImpl1(final CryptoConfig crypto_cfg,
                                                   final String[] enc_pub_keys,
                                                   final String sign_sec_key_fname, final String passphrase,
                                                   final String source_loc,
                                                   final String target_path, final String intention,
                                                   final String payload_version,
                                                   final String payload_version_parent,
                                                   final String destination_fname, final boolean overwrite,
                                                   final CipherpackListener listener);
 */
jobject Java_org_cipherpack_Cipherpack_encryptThenSignImpl1(JNIEnv *env, jclass jclazz,
        jobject jccfg, jobjectArray jenc_pub_keys,
        jstring jsign_sec_key_fname, jstring jpassphrase,
        jstring jsource_loc,
        jstring jtarget_path, jstring jintention,
        jstring jpayload_version,
        jstring jpayload_version_parent,
        jstring jdestination_fname, jboolean joverwrite,
        jobject cpListener)
{
    try {
        jau::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done
        CryptoConfig ccfg = jcipherpack::to_CryptoConfig(env, jccfg);

        const size_t enc_pub_keys_size = env->GetArrayLength(jenc_pub_keys);
        if( 0 >= enc_pub_keys_size ) {
            throw jau::IllegalArgumentException("enc_pub_keys array size "+std::to_string(enc_pub_keys_size)+" <= 0", E_FILE_LINE);
        }
        jau::JNICriticalArray<jobject, jobjectArray> criticalArray(env); // RAII - release
        jobject * enc_pub_keys_ptr = criticalArray.get(jenc_pub_keys, criticalArray.Mode::NO_UPDATE_AND_RELEASE);
        if( NULL == enc_pub_keys_ptr ) {
            throw jau::InternalError("GetPrimitiveArrayCritical(address enc_pub_keys array) is null", E_FILE_LINE);
        }
        std::vector<std::string> enc_pub_keys;
        for(size_t i=0; i<enc_pub_keys_size; ++i) {
            std::string enc_pub_key = jau::from_jstring_to_string(env, (jstring)enc_pub_keys_ptr[i]);
            enc_pub_keys.push_back(enc_pub_key);
        }

        std::string sign_sec_key_fname = jau::from_jstring_to_string(env, jsign_sec_key_fname);
        std::string passphrase = jau::from_jstring_to_string(env, jpassphrase);

        std::string source_loc = jau::from_jstring_to_string(env, jsource_loc);
        std::unique_ptr<jau::io::ByteInStream> source;
        const std::string proto = source_loc.substr(0, 5);
        if( proto == "http:" ) {
            source = std::make_unique<jau::io::ByteInStream_URL>(source_loc, 10_s);
        } else {
            source = std::make_unique<jau::io::ByteInStream_File>(source_loc, true /* use_binary */);
        }

        std::string target_path = jau::from_jstring_to_string(env, jtarget_path);
        std::string intention = jau::from_jstring_to_string(env, jintention);
        std::string payload_version = jau::from_jstring_to_string(env, jpayload_version);
        std::string payload_version_parent = jau::from_jstring_to_string(env, jpayload_version_parent);
        std::string destination_fname = jau::from_jstring_to_string(env, jdestination_fname);

        PackHeader ph = encryptThenSign(ccfg, enc_pub_keys, sign_sec_key_fname, passphrase, *source,
                                        target_path, intention, payload_version, payload_version_parent, refListener.shared_ptr());

        jobject jph = jcipherpack::to_jPackHeader(env, ph);

        return jph;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}


