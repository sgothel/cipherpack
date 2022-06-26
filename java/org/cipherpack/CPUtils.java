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
package org.cipherpack;

import java.io.PrintStream;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

public class CPUtils {
    private static long t0;
    static {
        t0 = startupTimeMillisImpl();
    }
    private static native long startupTimeMillisImpl();

    /**
     * Returns current monotonic time in milliseconds.
     */
    public static native long currentTimeMillis();

    /**
     * Returns current wall-clock system `time of day` in seconds since Unix Epoch
     * `00:00:00 UTC on 1 January 1970`.
     */
    public static native long wallClockSeconds();

    /**
     * Returns the startup time in monotonic time in milliseconds of the native module.
     */
    public static long startupTimeMillis() { return t0; }

    /**
     * Returns current elapsed monotonic time in milliseconds since module startup, see {@link #startupTimeMillis()}.
     */
    public static long elapsedTimeMillis() { return currentTimeMillis() - t0; }

    /**
     * Returns elapsed monotonic time in milliseconds since module startup comparing against the given timestamp, see {@link #startupTimeMillis()}.
     */
    public static long elapsedTimeMillis(final long current_ts) { return current_ts - t0; }

    /**
     * Convenient {@link PrintStream#printf(String, Object...)} invocation, prepending the {@link #elapsedTimeMillis()} timestamp.
     * @param out the output stream
     * @param format the format
     * @param args the arguments
     */
    public static void fprintf_td(final PrintStream out, final String format, final Object ... args) {
        out.printf("[%,9d] ", elapsedTimeMillis());
        out.printf(format, args);
    }
    /**
     * Convenient {@link PrintStream#println(String)} invocation, prepending the {@link #elapsedTimeMillis()} timestamp.
     * @param out the output stream
     * @param msg the string message
     */
    public static void println(final PrintStream out, final String msg) {
        out.printf("[%,9d] %s%s", elapsedTimeMillis(), msg, System.lineSeparator());
    }
    /**
     * Convenient {@link PrintStream#print(String)} invocation, prepending the {@link #elapsedTimeMillis()} timestamp.
     * @param out the output stream
     * @param msg the string message
     */
    public static void print(final PrintStream out, final String msg) {
        out.printf("[%,9d] %s", elapsedTimeMillis(), msg);
    }

    /**
     * Convert a non empty list to an array of same type.
     *
     * @param <E> the element type of the list
     * @param list the list instance
     * @throws IllegalArgumentException if given list instance is empty
     */
    @SuppressWarnings("unchecked")
    public static <E> E[] toArray(final List<E> list) throws IllegalArgumentException {
        if( 0 == list.size() ) {
            throw new IllegalArgumentException("Given list is empty");
        }
        final Class<E> clazz;
        {
            final E e0 = list.get(0);
            clazz = (Class<E>) e0.getClass();
        }
        final E[] res = (E[]) Array.newInstance(clazz, list.size());
        for(int i=0; i < res.length; ++i) {
            res[i] = list.get(i);
        }
        return res;
    }

    /**
     * Allocates a new direct ByteBuffer with the specified number of
     * elements. The returned buffer will have its byte order set to
     * the host platform's native byte order.
     */
    public static ByteBuffer newDirectByteBuffer(final int numElements) {
        return nativeOrder(ByteBuffer.allocateDirect(numElements));
    }

    /**
     * Helper routine to set a ByteBuffer to the native byte order, if
     * that operation is supported by the underlying NIO
     * implementation.
     */
    public static ByteBuffer nativeOrder(final ByteBuffer buf) {
        return buf.order(ByteOrder.nativeOrder());
    }

    /**
     * Zeros all bytes of given direct NIO byte buffer.
     */
    public static native void zeroByteBuffer(final ByteBuffer buf);

    /**
     * Zeros all underlying bytes of given Java string.
     *
     * Implementation either uses the JNI GetStringCritical() with is_copy == false or the String backing array `value`.
     *
     * @return true if successful, i.e. the underlying bytes could have been zeroed, otherwise returns false w/o zero'ed content.
    public static native boolean zeroString(final String str);
     */

    /**
     * Converts the Java string to a native direct ByteBuffer as UTF-8
     * allowing better control over its memory region to {@link #zeroByteBuffer(ByteBuffer) zero} it after usage.
     *
     * @param str the string to convert
     * @param zerostr pass true to zero the bytes of the given Java string afterwards (recommended!)
     * @return direct ByteBuffer instance suitable for Cipherpack.
    public static ByteBuffer to_ByteBuffer(final String str, final boolean zerostr) {
        final ByteBuffer res = toByteBufferImpl(str);
        res.limit(res.capacity());
        res.position(0);
        if( zerostr ) {
            zeroString(str);
        }
        return res;
    }
    private static native ByteBuffer toByteBufferImpl(final String str);

    public static String to_String(final ByteBuffer bb, final Charset cs) {
        final int p0 = bb.position();
        bb.position(0);
        final byte[] bb_bytes = new byte[bb.limit()];
        bb.get(bb_bytes);
        bb.position(p0);
        return new String(bb_bytes, cs);
    }
     */

}