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

#include "org_cipherpack_CipherpackListener.h"

// #define VERBOSE_ON 1
#include <jau/debug.hpp>

#include "cipherpack/cipherpack.hpp"

#include "CipherpackHelper.hpp"

// static const std::string _contentTypeClassName("org/cipherpack/CipherpackListener/ContentType");
// static const std::string _contentTypeClazzGetArgs("(B)Lorg/cipherpack/CipherpackListener/ContentType;");
static const std::string _notifyErrorMethodArgs("(ZLorg/cipherpack/PackHeader;Ljava/lang/String;)V");
static const std::string _notifyHeaderMethodArgs("(ZLorg/cipherpack/PackHeader;)Z");
static const std::string _notifyProgressMethodArgs("(ZJJ)Z");
static const std::string _notifyEndMethodArgs("(ZLorg/cipherpack/PackHeader;)V");
static const std::string _getSendContentMethodArgs("(Z)Z");
static const std::string _contentProcessedImplMethodArgs("(ZZ[BZ)Z");

class JNICipherpackListener : public cipherpack::CipherpackListener {
  private:
    static std::atomic<int> iname_next;
    int const iname;

    // jau::jni::JNIGlobalRef contentTypeClazzRef;
    // jmethodID contentTypeClazzGet;
    jmethodID  mNotifyError = nullptr;
    jmethodID  mNotifyHeader = nullptr;
    jmethodID  mNotifyProgress = nullptr;
    jmethodID  mNotifyEnd = nullptr;
    jmethodID  mGetSendContent = nullptr;
    jmethodID  mContentProcessedImpl = nullptr;

  public:

    std::string toString() const noexcept override {
        return "JNICipherpackListener[this "+jau::to_hexstring(this)+", iname "+std::to_string(iname)+"]";
    }

    ~JNICipherpackListener() override {
        // listenerObjRef dtor will call notifyDelete and clears the nativeInstance handle
    }

    JNICipherpackListener(JNIEnv *env, jobject cpListenerObj)
    : iname(iname_next.fetch_add(1))
    {
#if 0
        // contentTypeClazzRef, contentTypeClazzGet
        {
            jclass contentTypeClazz = jau::jni::search_class(env, _contentTypeClassName.c_str());
            contentTypeClazzRef = jau::jni::JNIGlobalRef(contentTypeClazz);
            env->DeleteLocalRef(contentTypeClazz);
        }
        contentTypeClazzGet = jau::jni::search_method(env, contentTypeClazzRef.getClass(), "get", _contentTypeClazzGetArgs.c_str(), true);
#endif

        jclass cpListenerClazz = jau::jni::search_class(env, cpListenerObj);

        mNotifyError = jau::jni::search_method(env, cpListenerClazz, "notifyError", _notifyErrorMethodArgs.c_str(), false);
        mNotifyHeader = jau::jni::search_method(env, cpListenerClazz, "notifyHeader", _notifyHeaderMethodArgs.c_str(), false);
        mNotifyProgress = jau::jni::search_method(env, cpListenerClazz, "notifyProgress", _notifyProgressMethodArgs.c_str(), false);
        mNotifyEnd = jau::jni::search_method(env, cpListenerClazz, "notifyEnd", _notifyEndMethodArgs.c_str(), false);
        mGetSendContent = jau::jni::search_method(env, cpListenerClazz, "getSendContent", _getSendContentMethodArgs.c_str(), false);
        mContentProcessedImpl = jau::jni::search_method(env, cpListenerClazz, "contentProcessedImpl", _contentProcessedImplMethodArgs.c_str(), false);
    }

    void notifyError(const bool decrypt_mode, const cipherpack::PackHeader& header, const std::string& msg) noexcept override {
        JNIEnv *env = *jau::jni::jni_env;
        jau::jni::JavaAnonRef asl_java = getJavaObject(); // hold until done!
        jau::jni::JavaGlobalObj::check(asl_java, E_FILE_LINE);
        jobject jph = jcipherpack::to_jPackHeader(env, header);
        jstring jmsg = jau::jni::from_string_to_jstring(env, msg);
        env->CallVoidMethod(jau::jni::JavaGlobalObj::GetObject(asl_java), mNotifyError,
                            decrypt_mode ? JNI_TRUE : JNI_FALSE,
                            jph,
                            jmsg);
        jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);
        env->DeleteLocalRef(jmsg);
    }

    bool notifyHeader(const bool decrypt_mode, const cipherpack::PackHeader& header) noexcept override {
        JNIEnv *env = *jau::jni::jni_env;
        jau::jni::JavaAnonRef asl_java = getJavaObject(); // hold until done!
        jau::jni::JavaGlobalObj::check(asl_java, E_FILE_LINE);
        jobject jph = jcipherpack::to_jPackHeader(env, header);
        jboolean res = env->CallBooleanMethod(jau::jni::JavaGlobalObj::GetObject(asl_java), mNotifyHeader,
                            decrypt_mode ? JNI_TRUE : JNI_FALSE,
                            jph);
        jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);
        env->DeleteLocalRef(jph);
        return JNI_TRUE == res;
    }

    bool notifyProgress(const bool decrypt_mode, const uint64_t plaintext_size, const uint64_t bytes_processed) noexcept override {
        JNIEnv *env = *jau::jni::jni_env;
        jau::jni::JavaAnonRef asl_java = getJavaObject(); // hold until done!
        jau::jni::JavaGlobalObj::check(asl_java, E_FILE_LINE);
        jboolean res = env->CallBooleanMethod(jau::jni::JavaGlobalObj::GetObject(asl_java), mNotifyProgress,
                            decrypt_mode ? JNI_TRUE : JNI_FALSE,
                            static_cast<jlong>(plaintext_size),
                            static_cast<jlong>(bytes_processed));
        jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);
        return JNI_TRUE == res;
    }

    void notifyEnd(const bool decrypt_mode, const cipherpack::PackHeader& header) noexcept override {
        JNIEnv *env = *jau::jni::jni_env;
        jau::jni::JavaAnonRef asl_java = getJavaObject(); // hold until done!
        jau::jni::JavaGlobalObj::check(asl_java, E_FILE_LINE);
        jobject jph = jcipherpack::to_jPackHeader(env, header);
        env->CallVoidMethod(jau::jni::JavaGlobalObj::GetObject(asl_java), mNotifyEnd,
                            decrypt_mode ? JNI_TRUE : JNI_FALSE,
                            jph);
        jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);
        env->DeleteLocalRef(jph);
    }

    bool getSendContent(const bool decrypt_mode) const noexcept override {
        JNIEnv *env = *jau::jni::jni_env;
        JNICipherpackListener * mthis = const_cast<JNICipherpackListener*>(this);
        jau::jni::JavaAnonRef asl_java = mthis->getJavaObject(); // hold until done!
        jau::jni::JavaGlobalObj::check(asl_java, E_FILE_LINE);
        jboolean res = env->CallBooleanMethod(jau::jni::JavaGlobalObj::GetObject(asl_java), mGetSendContent,
                            decrypt_mode ? JNI_TRUE : JNI_FALSE);
        jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);
        return JNI_TRUE == res;
    }

    bool contentProcessed(const bool decrypt_mode, const content_type ctype, cipherpack::secure_vector<uint8_t>& data, const bool is_final) noexcept override {
        JNIEnv *env = *jau::jni::jni_env;
        jau::jni::JavaAnonRef asl_java = getJavaObject(); // hold until done!
        jau::jni::JavaGlobalObj::check(asl_java, E_FILE_LINE);

#if 0
        jobject jcontentType = env->CallStaticObjectMethod(contentTypeClazzRef.getClass(), contentTypeClazzGet, static_cast<uint8_t>(ctype));
        jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);
#endif

        // TODO: Consider using a cached buffer of some sort, avoiding: (1) memory allocation, (2) copy the data
        // Avoiding copy the data will be hard though ..
        jbyteArray jdata = jau::jni::convert_bytes_to_jbytearray(env, data);

        jboolean res = env->CallBooleanMethod(jau::jni::JavaGlobalObj::GetObject(asl_java), mContentProcessedImpl,
                            decrypt_mode ? JNI_TRUE : JNI_FALSE,
                            // jcontentType,
                            content_type::header == ctype ? JNI_TRUE : JNI_FALSE,
                            jdata,
                            is_final ? JNI_TRUE : JNI_FALSE);
        jau::jni::java_exception_check_and_throw(env, E_FILE_LINE);
        env->DeleteLocalRef(jdata);
        return JNI_TRUE == res;
    }
};
std::atomic<int> JNICipherpackListener::iname_next(0);

/*
 * Class:     org_cipherpack_CipherpackListener
 * Method:    ctorImpl
 * Signature: ()J
 */
jlong Java_org_cipherpack_CipherpackListener_ctorImpl(JNIEnv *env, jobject obj) {
    try {
        cipherpack::environment::get();

        // new instance
        jau::jni::shared_ptr_ref<JNICipherpackListener> ref( new JNICipherpackListener(env, obj) );

        return ref.release_to_jlong();
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return (jlong) (intptr_t) nullptr;
}


/*
 * Class:     org_cipherpack_CipherpackListener
 * Method:    deleteImpl
 * Signature: (J)V
 */
void Java_org_cipherpack_CipherpackListener_deleteImpl(JNIEnv *env, jobject obj, jlong nativeInstance) {
    (void)obj;
    try {
        jau::jni::shared_ptr_ref<JNICipherpackListener> sref(nativeInstance, false /* throw_on_nullptr */); // hold copy until done
        if( nullptr != sref.pointer() ) {
            std::shared_ptr<JNICipherpackListener>* sref_ptr = jau::jni::castInstance<JNICipherpackListener>(nativeInstance);
            delete sref_ptr;
        }
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
}

