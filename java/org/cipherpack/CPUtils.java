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

}
