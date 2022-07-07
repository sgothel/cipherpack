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
import java.util.Iterator;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.jau.io.PrintUtil;
import org.jau.util.JauVersion;
import org.jau.util.VersionUtil;

/**
 * This {@code jaulib} derived version info class is only
 * usable when having {@code jaulib} available, naturally.
 */
public class CPVersion extends JauVersion {

    public static final void printVersionInfo(final PrintStream out) {
        CPFactory.initLibrary();

        PrintUtil.println(out, "CPFactory: Jaulib: Available "+CPFactory.JAULIB_AVAILABLE+", JarCache in use "+CPFactory.JAULIB_JARCACHE_USED);
        if( CPFactory.JAULIB_AVAILABLE ) {
            out.println(VersionUtil.getPlatformInfo());
            PrintUtil.println(out, "Version Info:");
            final CPVersion v = CPVersion.getInstance();
            out.println(v.toString());
            PrintUtil.println(out, "");
            PrintUtil.println(out, "Full Manifest:");
            out.println(v.getFullManifestInfo(null).toString());
        } else {
            PrintUtil.println(out, "Full Manifest:");
            final Manifest manifest = CPFactory.getManifest(CPFactory.class.getClassLoader(), new String[] { "org.cipherpack" } );
            final Attributes attr = manifest.getMainAttributes();
            final Set<Object> keys = attr.keySet();
            final StringBuilder sb = new StringBuilder();
            for(final Iterator<Object> iter=keys.iterator(); iter.hasNext(); ) {
                final Attributes.Name key = (Attributes.Name) iter.next();
                final String val = attr.getValue(key);
                sb.append(" ");
                sb.append(key);
                sb.append(" = ");
                sb.append(val);
                sb.append(System.lineSeparator());
            }
            out.println(sb.toString());
        }

        PrintUtil.println(out, "Cipherpack Native Version "+CPFactory.getNativeVersion()+" (API "+CPFactory.getNativeAPIVersion()+")");
        PrintUtil.println(out, "Cipherpack Java Version   "+CPFactory.getImplVersion()+" (API "+CPFactory.getAPIVersion()+")");
    }

    protected CPVersion(final String packageName, final Manifest mf) {
        super(packageName, mf);
    }

    /**
     * Returns a transient new instance.
     */
    public static CPVersion getInstance() {
        final String packageNameCompileTime = "org.cipherpack";
        final String packageNameRuntime = "org.cipherpack";
        Manifest mf = VersionUtil.getManifest(CPVersion.class.getClassLoader(), packageNameRuntime);
        if(null != mf) {
            return new CPVersion(packageNameRuntime, mf);
        } else {
            mf = VersionUtil.getManifest(CPVersion.class.getClassLoader(), packageNameCompileTime);
            return new CPVersion(packageNameCompileTime, mf);
        }
    }

    public static void main(final String args[]) {
        CPFactory.main(args);
    }
}
