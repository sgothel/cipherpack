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

#include "org_cipherpack_CPNativeDownlink.h"

#include <jau/debug.hpp>

#include "helper_base.hpp"

#include "cipherpack/cipherpack.hpp"

using namespace cipherpack;
using namespace jau;
using namespace jau::io;
using namespace jau::fractions_i64_literals;

/*
 * Class:     org_direct_bt_ByteInStream_Feed
 * Method:    ctorImpl
 * Signature: (Ljava/lang/String;J)J
 */
jlong Java_org_cipherpack_ByteInStream_Feed_ctorImpl(JNIEnv *env, jobject obj, jstring jid_name, jlong jtimeoutMS) {
    try {
        (void)obj;
        // new instance
        const std::string id_name = jau::from_jstring_to_string(env, jid_name);
        const jau::fraction_i64 timeout = jtimeoutMS * 1_ms;
        jau::shared_ptr_ref<ByteInStream_Feed> ref( new ByteInStream_Feed(id_name, timeout) );
        return ref.release_to_jlong();
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return (jlong) (intptr_t)nullptr;
}

/*
 * Class:     org_direct_bt_ByteInStream_Feed
 * Method:    dtorImpl
 * Signature: (J)V
 */
void Java_org_cipherpack_ByteInStream_Feed_dtorImpl(JNIEnv *env, jclass clazz, jlong nativeInstance) {
    (void)clazz;
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> sref(nativeInstance, false /* throw_on_nullptr */); // hold copy until done
        if( nullptr != sref.pointer() ) {
            std::shared_ptr<ByteInStream_Feed>* sref_ptr = jau::castInstance<ByteInStream_Feed>(nativeInstance);
            delete sref_ptr;
        }
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
}

jboolean Java_org_cipherpack_ByteInStream_Feed_end_of_data(JNIEnv *env, jobject obj) {
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> ref(env, obj); // hold until done
        return ref->end_of_data() ? JNI_TRUE : JNI_FALSE;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return JNI_TRUE;
}

jboolean Java_org_cipherpack_ByteInStream_Feed_error(JNIEnv *env, jobject obj) {
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> ref(env, obj); // hold until done
        return ref->error() ? JNI_TRUE : JNI_FALSE;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return JNI_TRUE;
}

/*
 * Class:     org_direct_bt_ByteInStream_Feed
 * Method:    id
 * Signature: ()Ljava/lang/String;
 */
jstring Java_org_cipherpack_ByteInStream_Feed_id(JNIEnv *env, jobject obj) {
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> ref(env, obj); // hold until done
        return jau::from_string_to_jstring(env, ref->id());
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return nullptr;
}


/*
 * Class:     org_direct_bt_ByteInStream_Feed
 * Method:    get_bytes_read
 * Signature: ()J
 */
jlong Java_org_cipherpack_ByteInStream_Feed_get_bytes_read(JNIEnv *env, jobject obj) {
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> ref(env, obj); // hold until done
        return static_cast<jlong>( ref->get_bytes_read() );
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return 0;
}

jboolean Java_org_cipherpack_ByteInStream_Feed_has_content_size(JNIEnv *env, jobject obj) {
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> ref(env, obj); // hold until done
        return ref->has_content_size() ? JNI_TRUE : JNI_FALSE;
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return JNI_TRUE;
}

jlong Java_org_cipherpack_ByteInStream_Feed_content_size(JNIEnv *env, jobject obj) {
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> ref(env, obj); // hold until done
        return static_cast<jlong>( ref->content_size() );
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
    return 0;
}

void Java_org_cipherpack_ByteInStream_Feed_interruptReader(JNIEnv *env, jobject obj) {
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> ref(env, obj); // hold until done
        ref->interruptReader();
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
}

/*
 * Class:     org_direct_bt_ByteInStream_Feed
 * Method:    write
 * Signature: ([BII)V
 */
void Java_org_cipherpack_ByteInStream_Feed_write(JNIEnv *env, jobject obj, jbyteArray jin, jint joffset, jint jlength) {
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> ref(env, obj); // hold until done

        if( nullptr == jin ) {
            throw jau::IllegalArgumentException("address null", E_FILE_LINE);
        }
        const size_t in_size = env->GetArrayLength(jin);
        if( (size_t)joffset + (size_t)jlength > in_size ) {
            throw jau::IllegalArgumentException("input byte size "+std::to_string(in_size)+" < "+std::to_string(joffset)+" + "+std::to_string(jlength), E_FILE_LINE);
        }
        jau::JNICriticalArray<uint8_t, jbyteArray> criticalArray(env); // RAII - release
        uint8_t * in_ptr = criticalArray.get(jin, criticalArray.Mode::NO_UPDATE_AND_RELEASE);
        if( NULL == in_ptr ) {
            throw jau::InternalError("GetPrimitiveArrayCritical(address byte array) is null", E_FILE_LINE);
        }
        ref->write(in_ptr + joffset, jlength);
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
}

void Java_org_cipherpack_ByteInStream_Feed_set_eof(JNIEnv *env, jobject obj, jint jresult) {
    try {
        jau::shared_ptr_ref<ByteInStream_Feed> ref(env, obj); // hold until done
        ref->set_eof(static_cast<async_io_result_t>(jresult));
    } catch(...) {
        rethrow_and_raise_java_exception(env);
    }
}
