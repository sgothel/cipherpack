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

// #define VERBOSE_ON 1
#include <jau/debug.hpp>
#include "helper_base.hpp"

#include "CipherpackHelper.hpp"

static const std::string _cryptoConfigClassName("org/cipherpack/CryptoConfig");
static const std::string _cryptoConfigClazzCtorArgs("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V");

static const std::string _packHeaderClassName("org/cipherpack/PackHeader");
static const std::string _packHeaderClazzCtorArgs("(Ljava/lang/String;JJJLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lorg/cipherpack/CryptoConfig;[BLjava/util/List;ILjava/lang/String;[BZ)V");

cipherpack::CryptoConfig jcipherpack::to_CryptoConfig(JNIEnv *env, jobject jccfg) {
    std::string pk_type_ = jau::jni::getStringFieldValue(env, jccfg, "pk_type");
    std::string pk_fingerprt_hash_algo_ = jau::jni::getStringFieldValue(env, jccfg, "pk_fingerprt_hash_algo");
    std::string pk_enc_padding_algo_ = jau::jni::getStringFieldValue(env, jccfg, "pk_enc_padding_algo");
    std::string pk_enc_hash_algo_ = jau::jni::getStringFieldValue(env, jccfg, "pk_enc_hash_algo");
    std::string pk_sign_algo_ = jau::jni::getStringFieldValue(env, jccfg, "pk_sign_algo");
    std::string sym_enc_algo_ = jau::jni::getStringFieldValue(env, jccfg, "sym_enc_algo");
    size_t sym_enc_nonce_bytes_ = jau::jni::getLongFieldValue(env, jccfg, "sym_enc_nonce_bytes");

    return cipherpack::CryptoConfig(pk_type_,
                 pk_fingerprt_hash_algo_,
                 pk_enc_padding_algo_,
                 pk_enc_hash_algo_,
                 pk_sign_algo_,
                 sym_enc_algo_,
                 sym_enc_nonce_bytes_);
}

jobject jcipherpack::to_jCryptoConfig(JNIEnv *env, const cipherpack::CryptoConfig& ccfg) {
    jstring jpk_type = jau::jni::from_string_to_jstring(env, ccfg.pk_type);
    jstring jpk_fingerprt_hash_algo = jau::jni::from_string_to_jstring(env, ccfg.pk_fingerprt_hash_algo);
    jstring jpk_enc_padding_algo = jau::jni::from_string_to_jstring(env, ccfg.pk_enc_padding_algo);
    jstring jpk_enc_hash_algo = jau::jni::from_string_to_jstring(env, ccfg.pk_enc_hash_algo);
    jstring jpk_sign_algo = jau::jni::from_string_to_jstring(env, ccfg.pk_sign_algo);
    jstring jsym_enc_algo = jau::jni::from_string_to_jstring(env, ccfg.sym_enc_algo);
    jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);

    jclass cryptoConfigClazz = jau::jni::search_class(env, _cryptoConfigClassName.c_str());
    jmethodID cryptoConfigClazzCtor = jau::jni::search_method(env, cryptoConfigClazz, "<init>", _cryptoConfigClazzCtorArgs.c_str(), false);

    jobject jccfg = env->NewObject(cryptoConfigClazz, cryptoConfigClazzCtor,
            jpk_type, jpk_fingerprt_hash_algo, jpk_enc_padding_algo, jpk_enc_hash_algo,
            jpk_sign_algo, jsym_enc_algo, static_cast<jlong>(ccfg.sym_enc_nonce_bytes));
    jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);

    env->DeleteLocalRef(cryptoConfigClazz);

    env->DeleteLocalRef(jpk_type);
    env->DeleteLocalRef(jpk_fingerprt_hash_algo);
    env->DeleteLocalRef(jpk_enc_padding_algo);
    env->DeleteLocalRef(jpk_enc_hash_algo);
    env->DeleteLocalRef(jpk_sign_algo);
    env->DeleteLocalRef(jsym_enc_algo);
    jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);
    return jccfg;
}

jobject jcipherpack::to_jPackHeader(JNIEnv *env, const cipherpack::PackHeader& ph) {
    jstring jtarget_path = jau::jni::from_string_to_jstring(env, ph.target_path());
    jstring jsubject = jau::jni::from_string_to_jstring(env, ph.subject());
    jstring jpversion = jau::jni::from_string_to_jstring(env, ph.plaintext_version());
    jstring jpversion_parent = jau::jni::from_string_to_jstring(env, ph.plaintext_version_parent());

    const cipherpack::CryptoConfig& ccfg = ph.crypto_config();
    jobject jccfg = to_jCryptoConfig(env, ccfg);

    jbyteArray jsender_fprint = jau::jni::convert_bytes_to_jbytearray(env, ph.sender_fingerprint());
    const std::vector<std::vector<uint8_t>>& recevr_fprints = ph.receiver_fingerprints();
    jobject jrecevr_fprints = jau::jni::convert_vector_bytes_to_jarraylist(env, recevr_fprints);
    jstring jplaintext_hash_algo = jau::jni::from_string_to_jstring(env, ph.plaintext_hash_algo());
    jbyteArray jplaintext_hash = jau::jni::convert_bytes_to_jbytearray(env, ph.plaintext_hash());

    jclass packHeaderClazz = jau::jni::search_class(env, _packHeaderClassName.c_str());
    jmethodID packHeaderClazzCtor = jau::jni::search_method(env, packHeaderClazz, "<init>", _packHeaderClazzCtorArgs.c_str(), false);

    jobject jph = env->NewObject(packHeaderClazz, packHeaderClazzCtor,
            jtarget_path,
            static_cast<jlong>(ph.plaintext_size()),
            static_cast<jlong>(ph.creation_time().tv_sec),
            static_cast<jlong>(ph.creation_time().tv_nsec),
            jsubject,
            jpversion, jpversion_parent,
            jccfg,
            jsender_fprint,
            jrecevr_fprints,
            ph.receiver_key_index(),
            jplaintext_hash_algo,
            jplaintext_hash,
            ph.isValid());
    jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);

    env->DeleteLocalRef(packHeaderClazz);

    env->DeleteLocalRef(jtarget_path);
    env->DeleteLocalRef(jsubject);
    env->DeleteLocalRef(jpversion);
    env->DeleteLocalRef(jpversion_parent);
    env->DeleteLocalRef(jccfg);
    env->DeleteLocalRef(jsender_fprint);
    env->DeleteLocalRef(jrecevr_fprints);
    return jph;
}


