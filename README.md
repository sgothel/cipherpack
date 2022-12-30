# Cipherpack - A Cryprographic Stream Processor

[Original document location](https://jausoft.com/cgit/cipherpack.git/about/).


## Git Repository
This project's canonical repositories is hosted on [Gothel Software](https://jausoft.com/cgit/cipherpack.git/).

## Overview
*Cipherpack*, a secure stream processor utilizing public-key signatures to
authenticate the sender and public-key encryption of a symmetric-key for multiple receiver
ensuring their privacy and high-performance message encryption.

*Cipherpack* securely streams messages through any media,
via file using 
[ByteInStream_File](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream__File.html)
and via all [*libcurl* network protocols](https://curl.se/docs/url-syntax.html) using 
[ByteInStream_URL](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream__URL.html)
are *build-in* and supported. <br/>
Note: *libcurl* must be [enabled via `-DUSE_LIBCURL=ON` at build](#build-procedure).

A user may use the media agnostic
[ByteInStream_Feed](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream__Feed.html)
to produce the input stream by injecting data off-thread and a 
[CipherpackListener](https://jausoft.com/projects/cipherpack/build/documentation/cpp/html/classcipherpack_1_1CipherpackListener.html)
to receive the processed output stream.

*Cipherpack* is implemented using C++17 or C++20 and is accessible via C++ and Java.

Please find the more detailed [overview in the API doc](https://jausoft.com/projects/cipherpack/build/documentation/cpp/html/group__CipherpackAPI.html#details).

Original use-case is a secure update process, elevating your installed firm- and software.<br/>
Hence original project name was *Elevator*.

See details on the [C++ and Java API](#cipherpack_apidoc) including its different C++ API level modules.

### Status
Build and clang-tidy clean on C++17 and C++20, passing all unit tests.

## Supported Platforms
Language requirements
- C++17 or C++20
- Java 11, 17+ (optional)

See [supported platforms](PLATFORMS.md) for details.

## Programming with Cipherpack

### API

<a name="cipherpack_apidoc"></a>

#### API Documentation
Up to date API documentation can be found:

* [C++ API Doc](https://jausoft.com/projects/cipherpack/build/documentation/cpp/html/group__CipherpackAPI.html#details)
  * [General User Level API](https://jausoft.com/projects/cipherpack/build/documentation/cpp/html/group__CipherpackAPI.html)

* [Java API Doc](https://jausoft.com/projects/cipherpack/build/documentation/java/html/classorg_1_1cipherpack_1_1Cipherpack.html#details)

* [jaulib Standalone C++ API Doc](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/index.html).


## Building Binaries

This project uses the following git submodules
- [Jau Library](https://jausoft.com/cgit/jaulib.git/about/)
- [Botan](https://github.com/randombit/botan.git)

### Build Dependencies
- CMake 3.13+ but >= 3.18 is recommended
- C++ compiler
  - gcc >= 8.3.0 (C++17)
  - gcc >= 10.2.1 (C++17 and C++20)
  - clang >= 15 (C++17 and C++20)
- Optional for `lint` validation
  - clang-tidy >= 15
- Optional for `vscodium` integration
  - clangd >= 15
  - clang-tools >= 15
  - clang-format >= 15
- Optional
  - libunwind8 >= 1.2.1
  - libcurl4 >= 7.74 (tested, lower may work)
- Optional Java support
  - OpenJDK >= 11
  - junit4 >= 4.12

#### Install on FreeBSD

Installing build dependencies on FreeBSD >= 13:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
pkg install git
pkg install sudo
pkg install cmake
pkg install libunwind
pkg install doxygen
pkg install squashfs-tools
pkg install bash
ln -s /usr/local/bin/bash /bin/bash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install optional Java dependencies:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
pkg install openjdk17
pkg install openjdk17-jre
pkg install junit
rehash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For Java ensure `/etc/fstab` includes:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
fdesc   /dev/fd         fdescfs         rw      0       0
proc    /proc           procfs          rw      0       0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`jau::fs::mount_image()` and `jau::fs::umount()` are currenly not
fully implemented under `FreeBSD`,
hence testing using cmake option `-DTEST_WITH_SUDO=ON` is disabled. <br />

To use URL streaming functionality via the `curl` library in `jau_io_util.hpp` and `jau/io_util.cpp`,
the cmake option `-DUSE_LIBCURL=ON` must be set. <br />
This also requires installation of the following packets:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
pkg install curl
apt install mini-httpd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Note: `mini-httpd` is being used for unit testing URL streaming only.

#### Install on Debian or Ubuntu

Installing build dependencies on Debian (10 or 11):
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
apt install git
apt install build-essential g++ gcc libc-dev libpthread-stubs0-dev 
apt install clang-15 clang-tidy-15 clangd-15 clang-tools-15 clang-format-15
apt install libunwind8 libunwind-dev
apt install cmake cmake-extras extra-cmake-modules pkg-config
apt install doxygen graphviz
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If using optional clang toolchain, 
perhaps change the clang version-suffix of above clang install line to the appropriate version.

After complete clang installation, you might want to setup the latest version as your default.
For Debian you can use this [clang alternatives setup script](https://jausoft.com/cgit/jaulib.git/tree/scripts/setup_clang_alternatives.sh).

Install optional Java dependencies:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
apt install openjdk-17-jdk openjdk-17-jre junit4
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To test `jau::fs::mount_image()` and `jau::fs::umount()` under `Linux`
with enabled cmake option `-DTEST_WITH_SUDO=ON`, <br />
the following build dependencies are added
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
apt install libcap-dev libcap2-bin
apt install squashfs-tools
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To use URL streaming functionality via the `curl` library in `jau_io_util.hpp` and `jau/io_util.cpp`,
the cmake option `-DUSE_LIBCURL=ON` must be set. <br />
This also requires installation of the following packets:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
apt install libcurl4 libcurl4-gnutls-dev
apt install mini-httpd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Note: `mini-httpd` is being used for unit testing URL streaming only.

### Build Procedure

To fetch the source tree use:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
git clone --recurse-submodule git://jausoft.com/srv/scm/cipherpack.git
cd cipherpack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

From here on we assume to be in the `cipherpack` project folder.

For a generic build use:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
CPU_COUNT=`getconf _NPROCESSORS_ONLN`
mkdir build
cd build
cmake -DBUILDJAVA=ON -DBUILDEXAMPLES=ON -DBUILD_TESTING=ON ..
make -j $CPU_COUNT install
make test
make doc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The install target of the last command will create the include/ and lib/ directories with a copy of
the headers and library objects respectively in your build location. Note that
doing an out-of-source build may cause issues when rebuilding later on.

You may also invoke `scripts/build.sh`,
which resolves installed environment variables like `JAVA_HOME` and `JUNIT_CP`
as well as building and distributing using `os_arch` type folders.
- `scripts/setup-machine-arch.sh` .. generic setup for all scripts
- `scripts/build.sh` .. initial build incl. install and unit testing
- `scripts/rebuild.sh` .. rebuild
- `scripts/build-cross.sh` .. [cross-build](#cross-build)
- `scripts/rebuild-cross.sh` .. [cross-build](#cross-build)
- `scripts/test_java.sh` .. invoke a java unit test
- `scripts/test_exe_template.sh` .. invoke the symlink'ed files to invoke native unit tests

Our cmake configure has a number of options, *cmake-gui* or *ccmake* can show
you all the options. The interesting ones are detailed below:

Changing install path from /usr/local to /usr
~~~~~~~~~~~~~
-DCMAKE_INSTALL_PREFIX=/usr
~~~~~~~~~~~~~

Building debug build:
~~~~~~~~~~~~~
-DDEBUG=ON
~~~~~~~~~~~~~

Add unit tests to build (default: disabled)
~~~~~~~~~~~~~
-DBUILD_TESTING=ON
~~~~~~~~~~~~~

Add unit tests requiring `sudo` to build (default: disabled).<br />
This option requires `-DBUILD_TESTING=ON` to be effective.<br />
Covered unit test requiring `sudo` are currently 
- `Linux` OS
  - `jau::fs::mount_image()`
  - `jau::fs::umount()`
~~~~~~~~~~~~~
-DTEST_WITH_SUDO=ON
~~~~~~~~~~~~~

Using clang instead of gcc:
~~~~~~~~~~~~~
-DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++
~~~~~~~~~~~~~

Building with clang and clang-tidy `lint` validation
~~~~~~~~~~~~~
-DCMAKE_C_COMPILER=/usr/bin/clang 
-DCMAKE_CXX_COMPILER=/usr/bin/clang++ 
-DCMAKE_CXX_CLANG_TIDY=/usr/bin/clang-tidy;-p;$rootdir/$build_dir
~~~~~~~~~~~~~

Disable stripping native lib even in non debug build:
~~~~~~~~~~~~~
-DUSE_STRIP=OFF
~~~~~~~~~~~~~

Enable using `libcurl` (default: disabled)
~~~~~~~~~~~~~
-DUSE_LIBCURL=ON
~~~~~~~~~~~~~

Enable using `libunwind` (default: disabled)
~~~~~~~~~~~~~
-DUSE_LIBUNWIND=ON
~~~~~~~~~~~~~

Disable using `C++ Runtime Type Information` (*RTTI*) (default: enabled)
~~~~~~~~~~~~~
-DDONT_USE_RTTI=ON
~~~~~~~~~~~~~

Building debug and instrumentation (sanitizer) build:
~~~~~~~~~~~~~
-DDEBUG=ON -DINSTRUMENTATION=ON
~~~~~~~~~~~~~

Cross-compiling on a different system:
~~~~~~~~~~~~~
-DCMAKE_CXX_FLAGS:STRING=-m32 -march=i586
-DCMAKE_C_FLAGS:STRING=-m32 -march=i586
~~~~~~~~~~~~~

To build documentation run: 
~~~~~~~~~~~~~
make doc
~~~~~~~~~~~~~

## IDE Integration

### Eclipse 
IDE integration configuration files are provided for 
- [Eclipse](https://download.eclipse.org/eclipse/downloads/) with extensions
  - [CDT](https://github.com/eclipse-cdt/) or [CDT @ eclipse.org](https://projects.eclipse.org/projects/tools.cdt)
  - Not used due to lack of subproject include file and symbol resolution:
    - `CMake Support`, install `C/C++ CMake Build Support` with ID `org.eclipse.cdt.cmake.feature.group`

From the project root directory, prepare the `Debug` folder using `cmake`
~~~~~~~~~~~~~
./scripts/eclipse-cmake-prepare.sh
~~~~~~~~~~~~~

The existing project setup is just using `external build` via `make`.

You can import the project to your workspace via `File . Import...` and `Existing Projects into Workspace` menu item.

For Eclipse one might need to adjust some setting in the `.project` and `.cproject` (CDT) 
via Eclipse settings UI, but it should just work out of the box.

### VSCodium or VS Code

IDE integration configuration files are provided for 
- [VSCodium](https://vscodium.com/) or [VS Code](https://code.visualstudio.com/) with extensions
  - [vscode-clangd](https://github.com/clangd/vscode-clangd)
  - [twxs.cmake](https://github.com/twxs/vs.language.cmake)
  - [ms-vscode.cmake-tools](https://github.com/microsoft/vscode-cmake-tools)
  - [notskm.clang-tidy](https://github.com/notskm/vscode-clang-tidy)
  - Java Support
    - [redhat.java](https://github.com/redhat-developer/vscode-java#readme)
      - Notable, `.settings/org.eclipse.jdt.core.prefs` describes the `lint` behavior
    - [vscjava.vscode-java-test](https://github.com/Microsoft/vscode-java-test)
    - [vscjava.vscode-java-debug](https://github.com/Microsoft/java-debug)
    - [vscjava.vscode-maven](https://github.com/Microsoft/vscode-maven/)
  - [cschlosser.doxdocgen](https://github.com/cschlosser/doxdocgen)
  - [jerrygoyal.shortcut-menu-bar](https://github.com/GorvGoyl/Shortcut-Menu-Bar-VSCode-Extension)

For VSCodium one might copy the [example root-workspace file](https://jausoft.com/cgit/cipherpack.git/tree/.vscode/cipherpack.code-workspace_example)
to the parent folder of this project (*note the filename change*) and adjust the `path` to your filesystem.
~~~~~~~~~~~~~
cp .vscode/cipherpack.code-workspace_example ../cipherpack.code-workspace
vi ../cipherpack.code-workspace
~~~~~~~~~~~~~
Then you can open it via `File . Open Workspace from File...` menu item.
- All listed extensions are referenced in this workspace file to be installed via the IDE
- The [local settings.json](.vscode/settings.json) has `clang-tidy` enabled
  - If using `clang-tidy` is too slow, just remove it from the settings file.
  - `clangd` will still contain a good portion of `clang-tidy` checks


## Support

*Cipherpack* is provided by [Gothel Software](https://jausoft.com/) and [Zafena ICT](https://ict.zafena.se).

If you like to utilize *Cipherpack* in a commercial setting, 
please contact [Gothel Software](https://jausoft.com/) to setup a potential support contract.


## Changes

**1.0.0**

* First stable release

**0.6.0**

* Completed restructuring incl. stream `CIPHERPACK_0003` and API doc
* Completed Java binding, all tests passed

**0.5.0**

* Renamed from Elevator to Cipherpack
* namespace elevator::cipherpack -> cipherpack
* Added pure streaming `encryptThenSign()` and `checkSignThenDecrypt()` base function


**0.4.0**

* Working version with universal jau::io::ByteInStream and matured unit testing OK and error cases


**0.0.0**

* Kick-off

