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

package test.org.cipherpack;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.cipherpack.CipherpackListener;
import org.cipherpack.PackHeader;
import org.junit.Assert;

public class LoggingCipherpackListener extends CipherpackListener {
    private final String name;
    private final boolean send_content;
    private boolean abort_header;
    private boolean abort_progress;
    private boolean abort_content;

    public AtomicInteger count_error = new AtomicInteger(0);
    public AtomicInteger count_header = new AtomicInteger(0);
    public AtomicInteger count_progress = new AtomicInteger(0);
    public AtomicInteger count_end = new AtomicInteger(0);
    public AtomicLong count_content = new AtomicLong(0);

    public LoggingCipherpackListener(final String name) {
        this(name, false);
    }
    public LoggingCipherpackListener(final String name, final boolean send_content) {
        super();
        this.name = name;
        this.send_content = send_content;
        this.abort_header = false;
        this.abort_progress = false;
        this.abort_content = false;
    }


    public void set_abort(final int what) {
        switch( what ) {
            case 1: set_abort_header(true); break;
            case 2: set_abort_progress(true); break;
            case 3: set_abort_content(true); break;
            default:
                Assert.assertTrue( false );
        }
    }
    public void set_abort_header(final boolean v) { abort_header = v; }
    public void set_abort_progress(final boolean v) { abort_progress = v; }
    public void set_abort_content(final boolean v) { abort_content = v; }

    public void check_counter_end() {
        check_counter_end(0);
    }
    public void check_counter_end(final long min_content) {
        if( abort_header ) {
            Assert.assertEquals( 0, count_error.get() );
            Assert.assertEquals( 1, count_header.get() );
            Assert.assertEquals( 0, count_progress.get() );
            Assert.assertEquals( 0, count_end.get() );
        } else if( abort_progress ) {
            Assert.assertEquals( 0, count_error.get() );
            Assert.assertEquals( 1, count_header.get() );
            Assert.assertEquals( 1, count_progress.get() );
            Assert.assertEquals( 0, count_end.get() );
        } else if( abort_content ) {
            Assert.assertEquals( 0, count_error.get() );
            Assert.assertEquals( 1, count_header.get() );
            Assert.assertEquals( 0, count_progress.get() );
            Assert.assertEquals( 0, count_end.get() );
        } else if( 0 < count_error.get() ) {
            if( 0 != count_header.get() && 1 != count_header.get() ) {
                Assert.assertTrue( false );
            }
            if( 0 != count_end.get() && 1 != count_end.get() ) {
                Assert.assertTrue( false );
            }
            Assert.assertTrue( 0 <= count_progress.get() );
        } else {
            Assert.assertEquals( 1, count_header.get() );
            Assert.assertEquals( 1, count_end.get() );
            Assert.assertTrue( 0 < count_progress.get() );
        }
        if( send_content ) {
            Assert.assertTrue( min_content <= count_content.get() );
        } else {
            Assert.assertEquals( 0, count_content.get() );
        }
    }

    @Override
    public void notifyError(final boolean decrypt_mode, final PackHeader header, final String msg) {
        count_error.incrementAndGet();
    }

    @Override
    public boolean notifyHeader(final boolean decrypt_mode, final PackHeader header) {
        count_header.incrementAndGet();
        return abort_header ? false : true;
    }

    @Override
    public boolean notifyProgress(final boolean decrypt_mode, final long plaintext_size, final long bytes_processed) {
        count_progress.incrementAndGet();
        return abort_progress ? false : true;
    }

    @Override
    public void notifyEnd(final boolean decrypt_mode, final PackHeader header) {
        count_end.incrementAndGet();
    }

    @Override
    public boolean getSendContent(final boolean decrypt_mode) {
        return send_content;
    }

    @Override
    public boolean contentProcessed(final boolean decrypt_mode, final ContentType ctype, final byte[] data, final boolean is_final) {
        count_content.addAndGet(data.length);
        return abort_content ? false : true;
    }

    @Override
    public String toString() {
        return "LoggingCipherpackListener["+name+"]";
    }
}
