# Cipherpack - A Cryprographic Stream Processor

[Original document location](https://jausoft.com/cgit/cipherpack.git/about/).


## Git Repository
This project's canonical repositories is hosted on [Gothel Software](https://jausoft.com/cgit/cipherpack.git/).

## Overview
*Cipherpack*, a secure stream processor utilizing public-key signatures to
authenticate the sender and public-key encryption of a symmetric-key for multiple receiver
ensuring their privacy and high-performance payload encryption.

A *Cipherpack* can be understood as a message, which can be streamed 
via any media while file and all [*libcurl* network protocols](https://curl.se/libcurl/) are *build-in* and supported.

A user may utilize the media agnostic API, a [ByteInStream_Feed](https://jausoft.com/projects/jaulib/build/documentation/cpp/html/classjau_1_1io_1_1ByteInStream__Feed.html)
to produce the input stream
and a CipherpackListener to receive the processed output stream.

*Cipherpack* is implemented using C++17 and accessible via C++ and Java.

Please find the more detailed [overview in the API doc](https://jausoft.com/projects/cipherpack/build/documentation/cpp/html/group__CipherpackAPI.html#details).

Original use-case is a secure update process, elevating your installed firm- and software.<br/>
Hence original project name was *Elevator*.

See details on the [C++ and Java API](#cipherpack_apidoc) including its different C++ API level modules.

## Supported Platforms

C++17 and better.

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

Installing build dependencies on Debian (10 or 11):
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
apt install git
apt install build-essential g++ gcc libc-dev libpthread-stubs0-dev 
apt install libunwind8 libunwind-dev
apt install cmake cmake-extras extra-cmake-modules pkg-config
apt install doxygen graphviz
apt install libcurl4 libcurl4-gnutls-dev
apt install mini-httpd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
make -j $CPU_COUNT install test doc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The install target of the last command will create the include/ and lib/ directories with a copy of
the headers and library objects respectively in your build location. Note that
doing an out-of-source build may cause issues when rebuilding later on.

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

Disable stripping native lib even in non debug build:
~~~~~~~~~~~~~
-DUSE_STRIP=OFF
~~~~~~~~~~~~~

Disable using `libunwind` (default: enabled for all but `arm32`, `armhf`)
~~~~~~~~~~~~~
-DUSE_LIBUNWIND=OFF
~~~~~~~~~~~~~

Disable using `C++ Runtime Type Information` (*RTTI*) (default: enabled)
~~~~~~~~~~~~~
-DDONT_USE_RTTI=ON
~~~~~~~~~~~~~

Building debug and instrumentation (sanitizer) build:
~~~~~~~~~~~~~
-DDEBUG=ON -DINSTRUMENTATION=ON
~~~~~~~~~~~~~

Using clang instead of gcc:
~~~~~~~~~~~~~
-DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++
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


## Support

*Cipherpack* is provided by [Gothel Software](https://jausoft.com/) and [Zafena ICT](https://ict.zafena.se).

If you like to utilize *Cipherpack* in a commercial setting, 
please contact [Gothel Software](https://jausoft.com/) to setup a potential support contract.


## Changes

**1.0.0**

* First stable release (TODO)

**0.5.0**

* Renamed from Elevator to Cipherpack
* namespace elevator::cipherpack -> cipherpack
* Added pure streaming `encryptThenSign()` and `checkSignThenDecrypt()` base function


**0.4.0**

* Working version with universal jau::io::ByteInStream and matured unit testing OK and error cases


**0.0.0**

* Kick-off

