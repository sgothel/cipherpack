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
#include "org_cipherpack_Cipherpack_HashUtil.h"

// #define VERBOSE_ON 1
#include <jau/basic_types.hpp>
#include <jau/debug.hpp>

#include "cipherpack/cipherpack.hpp"

#include "CipherpackHelper.hpp"

jobject Java_org_cipherpack_Cipherpack_encryptThenSignImpl1(JNIEnv *env, jclass /*jclazz*/,
        jobject jccfg, jobject jenc_pub_keys,
        jstring jsign_sec_key_fname, jobject jpassphrase,
        jobject jsource_feed,
        jstring jtarget_path, jstring jsubject,
        jstring jplaintext_version,
        jstring jplaintext_version_parent,
        jobject cpListener,
        jstring jplaintext_hash_algo,
        jstring jdestination_fname)
{
    try {
        jau::jni::shared_ptr_ref<jau::io::ByteStream> refSource(env, jsource_feed); // hold until done
        jau::jni::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done

        cipherpack::CryptoConfig ccfg = jcipherpack::to_CryptoConfig(env, jccfg);
        std::vector<std::string> enc_pub_keys = jau::jni::convert_jlist_string_to_vector(env, jenc_pub_keys);
        std::string sign_sec_key_fname = jau::jni::from_jstring_to_string(env, jsign_sec_key_fname);
        jau::io::secure_string passphrase = nullptr != jpassphrase ? jau::jni::from_jbytebuffer_to_sstring(env, jpassphrase) : jau::io::secure_string();
        std::string target_path = jau::jni::from_jstring_to_string(env, jtarget_path);
        std::string subject = jau::jni::from_jstring_to_string(env, jsubject);
        std::string plaintext_version = jau::jni::from_jstring_to_string(env, jplaintext_version);
        std::string plaintext_version_parent = jau::jni::from_jstring_to_string(env, jplaintext_version_parent);
        std::string plaintext_hash_algo = jau::jni::from_jstring_to_string(env, jplaintext_hash_algo);
        std::string destination_fname = nullptr != jdestination_fname ? jau::jni::from_jstring_to_string(env, jdestination_fname) : "";

        cipherpack::PackHeader ph = encryptThenSign(ccfg, enc_pub_keys, sign_sec_key_fname, passphrase, *refSource,
                                                    target_path, subject, plaintext_version, plaintext_version_parent,
                                                    refListener.shared_ptr(), plaintext_hash_algo, destination_fname);
        jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);

        jobject jph = jcipherpack::to_jPackHeader(env, ph);

        return jph;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}

jobject Java_org_cipherpack_Cipherpack_checkSignThenDecrypt1(JNIEnv *env, jclass /*jclazz*/,
        jobject jsign_pub_keys,
        jstring jdec_sec_key_fname, jobject jpassphrase,
        jobject jsource_feed,
        jobject cpListener,
        jstring jplaintext_hash_algo,
        jstring jdestination_fname)
{
    try {
        jau::jni::shared_ptr_ref<jau::io::ByteStream> refSource(env, jsource_feed); // hold until done
        jau::jni::shared_ptr_ref<cipherpack::CipherpackListener> refListener(env, cpListener); // hold until done

        std::vector<std::string> sign_pub_keys = jau::jni::convert_jlist_string_to_vector(env, jsign_pub_keys);
        std::string dec_sec_key_fname = jau::jni::from_jstring_to_string(env, jdec_sec_key_fname);
        jau::io::secure_string passphrase = nullptr != jpassphrase ? jau::jni::from_jbytebuffer_to_sstring(env, jpassphrase) : jau::io::secure_string();
        std::string plaintext_hash_algo = jau::jni::from_jstring_to_string(env, jplaintext_hash_algo);
        std::string destination_fname = nullptr != jdestination_fname ? jau::jni::from_jstring_to_string(env, jdestination_fname) : "";

        cipherpack::PackHeader ph = checkSignThenDecrypt(sign_pub_keys, dec_sec_key_fname, passphrase, *refSource,
                                                         refListener.shared_ptr(), plaintext_hash_algo, destination_fname);
        jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);

        jobject jph = jcipherpack::to_jPackHeader(env, ph);

        return jph;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}

jbyteArray Java_org_cipherpack_Cipherpack_00024HashUtil_calcImpl1(JNIEnv *env, jclass /*jclazz*/, jstring jalgo, jobject jsource_feed) {
    try {
        jau::jni::shared_ptr_ref<jau::io::ByteStream> refSource(env, jsource_feed); // hold until done
        std::string algo = jau::jni::from_jstring_to_string(env, jalgo);

        std::unique_ptr<std::vector<uint8_t>> hash = cipherpack::hash_util::calc(algo, *refSource);
        if( nullptr == hash ) {
            return nullptr;
        }
        jbyteArray jhash = jau::jni::convert_bytes_to_jbytearray(env, *hash);
        return jhash;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}

jbyteArray Java_org_cipherpack_Cipherpack_00024HashUtil_calcImpl2(JNIEnv *env, jclass /*jclazz*/, jstring jalgo, jstring jpath_or_uri, jlongArray jbytes_hashed, jlong jtimeoutMS) {
    try {
        std::string algo = jau::jni::from_jstring_to_string(env, jalgo);
        std::string path_or_uri = jau::jni::from_jstring_to_string(env, jpath_or_uri);
        const jau::fraction_i64 timeout = (int64_t)jtimeoutMS * 1_ms;

        if( nullptr == jbytes_hashed ) {
            throw jau::IllegalArgumentError("bytes_hashed null", E_FILE_LINE);
        }
        const size_t bh_size = env->GetArrayLength(jbytes_hashed);
        if( 1 > bh_size ) {
            throw jau::IllegalArgumentError("bytes_hashed array size "+std::to_string(bh_size)+" < 1", E_FILE_LINE);
        }
        jau::jni::JNICriticalArray<uint64_t, jlongArray> criticalArray(env); // RAII - release
        uint64_t * bh_ptr = criticalArray.get(jbytes_hashed, criticalArray.Mode::UPDATE_AND_RELEASE);
        if( nullptr == bh_ptr ) {
            throw jau::InternalError("GetPrimitiveArrayCritical(address byte array) is null", E_FILE_LINE);
        }

        std::unique_ptr<std::vector<uint8_t>> hash = cipherpack::hash_util::calc(algo, path_or_uri, *bh_ptr, timeout);
        if( nullptr == hash ) {
            return nullptr;
        }
        jbyteArray jhash = jau::jni::convert_bytes_to_jbytearray(env, *hash);
        return jhash;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}
