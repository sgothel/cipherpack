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

import jau.test.junit.util.SingletonJunitCase;

import org.cipherpack.CPFactory;
import org.cipherpack.CPVersion;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Testing BTManager bring up using fat `Direct-BT Jaulib Fat Jar` and
 * - test loading native libraries
 * - show all installed adapter
 * - no extra permissions required
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Test01Cipherpack extends SingletonJunitCase {
    static final boolean DEBUG = false;

    @Test(timeout = 40000) // long timeout for valgrind
    public final void test01_ManagerBringup() {
        {
            // System.setProperty("cipherpack.debug", "true");
            System.setProperty("cipherpack.verbose", "true");
            // System.setProperty("jau.debug", "true"); // java
            // System.setProperty("jau.verbose", "true"); // java
        }
        CPFactory.checkInitialized();
        CPVersion.printVersionInfo(System.err);
    }

    public static void main(final String args[]) {
        org.junit.runner.JUnitCore.main(Test01Cipherpack.class.getName());
    }
}
