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

using namespace cipherpack;

static const std::string _cryptoConfigClassName("org/cipherpack/CryptoConfig");
static const std::string _cryptoConfigClazzCtorArgs("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V");

static const std::string _packHeaderClassName("org/cipherpack/PackHeader");
static const std::string _packHeaderClazzCtorArgs("(Ljava/lang/String;JJLjava/lang/String;IILorg/cipherpack/CryptoConfig;Ljava/lang/String;[Ljava/lang/String;IZ)V");

CryptoConfig jcipherpack::to_CryptoConfig(JNIEnv *env, jobject jccfg) {
    std::string pk_type_ = jau::getStringFieldValue(env, jccfg, "pk_type");
    std::string pk_fingerprt_hash_algo_ = jau::getStringFieldValue(env, jccfg, "pk_fingerprt_hash_algo");
    std::string pk_enc_padding_algo_ = jau::getStringFieldValue(env, jccfg, "pk_enc_padding_algo");
    std::string pk_enc_hash_algo_ = jau::getStringFieldValue(env, jccfg, "pk_enc_hash_algo");
    std::string pk_sign_algo_ = jau::getStringFieldValue(env, jccfg, "pk_sign_algo");
    std::string sym_enc_algo_ = jau::getStringFieldValue(env, jccfg, "sym_enc_algo");
    size_t sym_enc_nonce_bytes_ = jau::getLongFieldValue(env, jccfg, "sym_enc_nonce_bytes");

    return CryptoConfig(pk_type_,
                 pk_fingerprt_hash_algo_,
                 pk_enc_padding_algo_,
                 pk_enc_hash_algo_,
                 pk_sign_algo_,
                 sym_enc_algo_,
                 sym_enc_nonce_bytes_);
}

jobject jcipherpack::to_jCryptoConfig(JNIEnv *env, const CryptoConfig& ccfg) {
    // public CryptoConfig(final String pk_type_,
    //          final String pk_fingerprt_hash_algo_,
    //          final String pk_enc_padding_algo_,
    //          final String pk_enc_hash_algo_,
    //          final String pk_sign_algo_,
    //          final String sym_enc_algo_,
    //          final long sym_enc_nonce_bytes_) {
    jstring jpk_type = jau::from_string_to_jstring(env, ccfg.pk_type);
    jstring jpk_fingerprt_hash_algo = jau::from_string_to_jstring(env, ccfg.pk_fingerprt_hash_algo);
    jstring jpk_enc_padding_algo = jau::from_string_to_jstring(env, ccfg.pk_enc_padding_algo);
    jstring jpk_enc_hash_algo = jau::from_string_to_jstring(env, ccfg.pk_enc_hash_algo);
    jstring jpk_sign_algo = jau::from_string_to_jstring(env, ccfg.pk_sign_algo);
    jstring jsym_enc_algo = jau::from_string_to_jstring(env, ccfg.sym_enc_algo);
    jau::java_exception_check_and_throw(env, E_FILE_LINE);

    jclass cryptoConfigClazz = jau::search_class(env, _cryptoConfigClassName.c_str());
    jmethodID cryptoConfigClazzCtor = jau::search_method(env, cryptoConfigClazz, "<init>", _cryptoConfigClazzCtorArgs.c_str(), false);

    jobject jccfg = env->NewObject(cryptoConfigClazz, cryptoConfigClazzCtor,
            jpk_type, jpk_fingerprt_hash_algo, jpk_enc_padding_algo, jpk_enc_hash_algo,
            jpk_sign_algo, jsym_enc_algo, static_cast<jlong>(ccfg.sym_enc_nonce_bytes));
    jau::java_exception_check_and_throw(env, E_FILE_LINE);

    env->DeleteLocalRef(cryptoConfigClazz);

    env->DeleteLocalRef(jpk_type);
    env->DeleteLocalRef(jpk_fingerprt_hash_algo);
    env->DeleteLocalRef(jpk_enc_padding_algo);
    env->DeleteLocalRef(jpk_enc_hash_algo);
    env->DeleteLocalRef(jpk_sign_algo);
    env->DeleteLocalRef(jsym_enc_algo);
    jau::java_exception_check_and_throw(env, E_FILE_LINE);
    return jccfg;
}

jobject jcipherpack::to_jPackHeader(JNIEnv *env, const PackHeader& ph) {
    // PackHeader(final String target_path_,
    //            final long content_size_,
    //            final long ts_creation_,
    //            final String intention_,
    //            final String pversion, final String pversion_parent,
    //            final CryptoConfig crypto_cfg_,
    //            final String host_key_fingerprint_,
    //            final String[] term_keys_fingerprint_,
    //            final int term_key_fingerprint_used_idx_,
    //            final boolean valid_) {
    jstring jtarget_path = jau::from_string_to_jstring(env, ph.getTargetPath());
    jstring jintention = jau::from_string_to_jstring(env, ph.getIntention());
    jstring jpversion = jau::from_string_to_jstring(env, ph.getPayloadVersion());
    jstring jpversion_parent = jau::from_string_to_jstring(env, ph.getPayloadVersionParent());

    const CryptoConfig& ccfg = ph.getCryptoConfig();
    jobject jccfg = to_jCryptoConfig(env, ccfg);

    jstring jpk_host_key_fprint = jau::from_string_to_jstring(env, ph.getHostKeyFingerprint());
    const std::vector<std::string>& termKeysFingerprint = ph.getTermKeysFingerprint();
    jobject jtermKeysFingerprint = jau::convert_vector_string_to_jarraylist(env, termKeysFingerprint);
    jau::java_exception_check_and_throw(env, E_FILE_LINE);

    jclass packHeaderClazz = jau::search_class(env, _packHeaderClassName.c_str());
    jmethodID packHeaderClazzCtor = jau::search_method(env, packHeaderClazz, "<init>", _packHeaderClazzCtorArgs.c_str(), false);

    jobject jph = env->NewObject(packHeaderClazz, packHeaderClazzCtor,
            jtarget_path,
            static_cast<jlong>(ph.getContentSize()),
            static_cast<jlong>(ph.getCreationTime().to_fraction_i64().to_ms()),
            jintention,
            jpversion, jpversion_parent,
            jccfg,
            jpk_host_key_fprint,
            jtermKeysFingerprint,
            ph.getUsedTermKeyFingerprintIndex(),
            ph.isValid());
    jau::java_exception_check_and_throw(env, E_FILE_LINE);

    env->DeleteLocalRef(packHeaderClazz);

    env->DeleteLocalRef(jtarget_path);
    env->DeleteLocalRef(jintention);
    env->DeleteLocalRef(jpversion);
    env->DeleteLocalRef(jpversion_parent);
    env->DeleteLocalRef(jccfg);
    env->DeleteLocalRef(jpk_host_key_fprint);
    env->DeleteLocalRef(jtermKeysFingerprint);
    return jph;
}


