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

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.PrivilegedAction;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.jau.util.VersionUtil;

/**
 * Cipherpack Factory, called by automatically to load the native library.
 * <p>
 * Further provides access to certain property settings,
 * see {@link #DEBUG}, {@link #VERBOSE}.
 * </p>
 */
public class CPFactory {

    /**
     * Manifest's {@link Attributes.Name#SPECIFICATION_VERSION} or {@code null} if not available.
     */
    public static final String getAPIVersion() { return APIVersion; }
    private static String APIVersion;

    /**
     * Manifest's {@link Attributes.Name#IMPLEMENTATION_VERSION} or {@code null} if not available.
     */
    public static final String getImplVersion() { return ImplVersion; }
    private static String ImplVersion;

    /**
     * Verbose logging enabled or disabled.
     * <p>
     * System property {@code org.cipherpack.verbose}, boolean, default {@code false}.
     * </p>
     */
    public static final boolean VERBOSE;

    /**
     * Debug logging enabled or disabled.
     * <p>
     * System property {@code org.cipherpack.debug}, boolean, default {@code false}.
     * </p>
     */
    public static final boolean DEBUG;

    /**
     * True if jaulib {@link org.jau.sys.PlatformProps} has been detected.
     */
    public static final boolean JAULIB_AVAILABLE;

    /**
     * True if jaulib {@link #JAULIB_AVAILABLE} and its {@link org.jau.sys.PlatformProps#USE_TEMP_JAR_CACHE} is true,
     * i.e. the jar cache is available, enabled and in use.
     */
    public static final boolean JAULIB_JARCACHE_USED;

    /**
     * Deprecated call to {@link java.security.AccessController#doPrivileged(PrivilegedAction)} w/o warnings.
     * @param <T>
     * @param o
     * @return
     */
    @SuppressWarnings({ "deprecation", "removal" })
    public static <T> T doPrivileged(final PrivilegedAction<T> o) {
        return java.security.AccessController.doPrivileged( o );
    }

    private static final String implementationNativeLibraryBasename = "cipherpack";
    private static final String javaNativeLibraryBasename = "javacipherpack";

    private static AtomicBoolean initializedID = new AtomicBoolean(false);

    static {
        {
            final String v = System.getProperty("org.cipherpack.debug", "false");
            DEBUG = Boolean.valueOf(v);
        }
        if( DEBUG ) {
            VERBOSE = true;
        } else  {
            final String v = System.getProperty("org.cipherpack.verbose", "false");
            VERBOSE = Boolean.valueOf(v);
        }

        boolean isJaulibAvail = false;
        try {
            isJaulibAvail = null != Class.forName("org.jau.sys.RuntimeProps", true /* initializeClazz */, CPFactory.class.getClassLoader());
        } catch( final Throwable t ) {
            if( DEBUG ) {
                System.err.println("CPFactory Caught: "+t.getMessage());
                t.printStackTrace();
            }
        }
        JAULIB_AVAILABLE = isJaulibAvail;

        if( isJaulibAvail ) {
            JAULIB_JARCACHE_USED = org.jau.sys.RuntimeProps.USE_TEMP_JAR_CACHE;
        } else {
            JAULIB_JARCACHE_USED = false;
        }
        if( VERBOSE ) {
            System.err.println("Jaulib available: "+JAULIB_AVAILABLE+", JarCache in use: "+JAULIB_JARCACHE_USED);
        }

        final ClassLoader cl = CPFactory.class.getClassLoader();
        boolean libsLoaded = false;
        if( JAULIB_AVAILABLE ) {
            if( JAULIB_JARCACHE_USED ) {
                try {
                    org.jau.pkg.JNIJarLibrary.addNativeJarLibs(new Class<?>[] { CPFactory.class }, null);
                } catch (final Exception e0) {
                    System.err.println("CPFactory Caught "+e0.getClass().getSimpleName()+": "+e0.getMessage()+", while JNILibLoaderBase.addNativeJarLibs(..)");
                    if( DEBUG ) {
                        e0.printStackTrace();
                    }
                }
            }
            try {
                if( null != org.jau.sys.dl.NativeLibrary.open(implementationNativeLibraryBasename,
                                               true /* searchSystemPath */, false /* searchSystemPathFirst */, cl, true /* global */) )
                {
                    org.jau.sys.JNILibrary.loadLibrary(javaNativeLibraryBasename, false, cl);
                    libsLoaded = true;
                }
            } catch (final Throwable t) {
                System.err.println("Caught "+t.getClass().getSimpleName()+": "+t.getMessage()+", while loading libs..");
                if( DEBUG ) {
                    t.printStackTrace();
                }
            }
            if( DEBUG ) {
                System.err.println("Jaulib: Native libs loaded: "+ libsLoaded);
            }
        }
        if( !libsLoaded ) {
            try {
                final Throwable[] t = { null };
                if( !PlatformToolkit.loadLibrary(implementationNativeLibraryBasename, cl, t) ) {
                    throw new RuntimeException("Couldn't load native tool library with basename <"+implementationNativeLibraryBasename+">", t[0]);
                }
                if( !PlatformToolkit.loadLibrary(javaNativeLibraryBasename, cl, t) ) {
                    throw new RuntimeException("Couldn't load native java library with basename <"+javaNativeLibraryBasename+">", t[0]);
                }
            } catch (final Throwable e) {
                System.err.println("Caught "+e.getClass().getSimpleName()+": "+e.getMessage()+", while loading libs (2) ..");
                if( DEBUG ) {
                    e.printStackTrace();
                }
                throw e; // fwd exception - end here
            }
        }

        // Map all Java properties '[org.]cipherpack.*' and 'cipherpack.*' to native environment.
        try {
            if( DEBUG ) {
                System.err.println("CPFactory: Mapping '[org.|jau.]cipherpack.*' properties to native environment");
            }
            final Properties props = doPrivileged(new PrivilegedAction<Properties>() {
                  @Override
                  public Properties run() {
                      return System.getProperties();
                  } });

            final Enumeration<?> enums = props.propertyNames();
            while (enums.hasMoreElements()) {
              final String key = (String) enums.nextElement();
              if( key.startsWith("org.cipherpack.") || key.startsWith("jau.cipherpack.") ||
                  key.startsWith("cipherpack.") )
              {
                  final String value = props.getProperty(key);
                  if( DEBUG ) {
                      System.err.println("  <"+key+"> := <"+value+">");
                  }
                  setenv(key, value, true /* overwrite */);
              }
            }
        } catch (final Throwable e) {
            System.err.println("Caught exception while forwarding system properties: "+e.getMessage());
            e.printStackTrace();
        }

        try {
            final Manifest manifest = getManifest(cl, new String[] { "org.cipherpack" } );
            final Attributes mfAttributes = null != manifest ? manifest.getMainAttributes() : null;

            // major.minor must match!
            final String NAPIVersion = getNativeAPIVersion();
            final String JAPIVersion = null != mfAttributes ? mfAttributes.getValue(Attributes.Name.SPECIFICATION_VERSION) : null;
            if ( null != JAPIVersion && JAPIVersion.equals(NAPIVersion) == false) {
                final String[] NAPIVersionCode = NAPIVersion.split("\\D");
                final String[] JAPIVersionCode = JAPIVersion.split("\\D");
                if (JAPIVersionCode[0].equals(NAPIVersionCode[0]) == false) {
                    if (Integer.valueOf(JAPIVersionCode[0]) < Integer.valueOf(NAPIVersionCode[0])) {
                        throw new RuntimeException("Java library "+JAPIVersion+" < native library "+NAPIVersion+". Please update the Java library.");
                    } else {
                        throw new RuntimeException("Native library "+NAPIVersion+" < java library "+JAPIVersion+". Please update the native library.");
                    }
                } else if (JAPIVersionCode[1].equals(NAPIVersionCode[1]) == false) {
                    if (Integer.valueOf(JAPIVersionCode[1]) < Integer.valueOf(NAPIVersionCode[1])) {
                        throw new RuntimeException("Java library "+JAPIVersion+" < native library "+NAPIVersion+". Please update the Java library.");
                    } else {
                        throw new RuntimeException("Native library "+NAPIVersion+" < java library "+JAPIVersion+". Please update the native library.");
                    }
                }
            }
            initializedID.set( true ); // initialized!

            APIVersion = JAPIVersion;
            ImplVersion = null != mfAttributes ? mfAttributes.getValue(Attributes.Name.IMPLEMENTATION_VERSION) : null;
            if( VERBOSE ) {
                System.err.println("Cipherpack loaded");
                System.err.println("Cipherpack java api version "+JAPIVersion);
                System.err.println("Cipherpack native api version "+NAPIVersion);
                if( null != mfAttributes ) {
                    final Attributes.Name[] versionAttributeNames = new Attributes.Name[] {
                            Attributes.Name.SPECIFICATION_TITLE,
                            Attributes.Name.SPECIFICATION_VENDOR,
                            Attributes.Name.SPECIFICATION_VERSION,
                            Attributes.Name.IMPLEMENTATION_TITLE,
                            Attributes.Name.IMPLEMENTATION_VENDOR,
                            Attributes.Name.IMPLEMENTATION_VERSION,
                            new Attributes.Name("Implementation-Commit") };
                    for( final Attributes.Name an : versionAttributeNames ) {
                        System.err.println("  "+an+": "+mfAttributes.getValue(an));
                    }
                } else {
                    System.err.println("  No Manifest available;");
                }
            }
        } catch (final Throwable e) {
            System.err.println("Error querying manifest information.");
            e.printStackTrace();
            throw e; // fwd exception - end here
        }

    }

    public static void checkInitialized() {
        if( false == initializedID.get() ) {
            throw new IllegalStateException("Cipherpack not initialized.");
        }
    }
    public static boolean isInitialized() {
        return false != initializedID.get();
    }

    public static synchronized void initLibrary() {
        // tagging static init block
    }

    /**
     * Helper function to retrieve a Manifest instance.
     */
    public static final Manifest getManifest(final ClassLoader cl, final String[] extensions) {
        final Manifest[] extManifests = new Manifest[extensions.length];
        try {
            final Enumeration<URL> resources = cl.getResources("META-INF/MANIFEST.MF");
            while (resources.hasMoreElements()) {
                final URL resURL = resources.nextElement();
                if( DEBUG ) {
                    System.err.println("resource: "+resURL);
                }
                final InputStream is = resURL.openStream();
                final Manifest manifest;
                try {
                    manifest = new Manifest(is);
                } finally {
                    try {
                        is.close();
                    } catch (final IOException e) {}
                }
                final Attributes attributes = manifest.getMainAttributes();
                if(attributes != null) {
                    final String attributesExtName = attributes.getValue( Attributes.Name.EXTENSION_NAME );
                    for(int i=0; i < extensions.length && null == extManifests[i]; i++) {
                        final String extension = extensions[i];
                        if( extension.equals( attributesExtName ) ) {
                            if( 0 == i ) {
                                return manifest; // 1st one has highest prio - done
                            }
                            extManifests[i] = manifest;
                        }
                    }
                }
            }
        } catch (final IOException ex) {
            throw new RuntimeException("Unable to read manifest.", ex);
        }
        for(int i=1; i<extManifests.length; i++) {
            if( null != extManifests[i] ) {
                return extManifests[i];
            }
        }
        return null;
    }

    public static void main(final String args[]) {
        System.err.println("Jaulib: Available "+JAULIB_AVAILABLE+", JarCache in use "+JAULIB_JARCACHE_USED);
        if( JAULIB_AVAILABLE ) {
            System.err.println(VersionUtil.getPlatformInfo());
            System.err.println("Version Info:");
            final CPVersion v = CPVersion.getInstance();
            System.err.println(v);
            System.err.println("");
            System.err.println("Full Manifest:");
            System.err.println(v.getFullManifestInfo(null));
        } else {
            System.err.println("Full Manifest:");
            final Manifest manifest = getManifest(CPFactory.class.getClassLoader(), new String[] { "org.cipherpack" } );
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
            System.err.println(sb);
        }
        try {
            // FIXME
        } catch ( final Throwable t ) {
            t.printStackTrace();
        }
    }

    public native static String getNativeVersion();
    public native static String getNativeAPIVersion();
    private native static void setenv(String name, String value, boolean overwrite);
}

/** \example Cipherpack.java
 * This is the commandline version to convert a source from and to a cipherpack, i.e. encrypt and decrypt.
 */

/** \example Test01Cipherpack.java
 * Unit test, testing encrypting to and decrypting from a cipherpack stream using different sources.
 *
 * Unit test also covers error cases.
 */
