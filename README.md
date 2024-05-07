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

*Cipherpack* is implemented using C++20 and is accessible via C++ and Java.

Please find the more detailed [overview in the API doc](https://jausoft.com/projects/cipherpack/build/documentation/cpp/html/group__CipherpackAPI.html#details).

Original use-case is a secure update process, elevating your installed firm- and software.<br/>
Hence original project name was *Elevator*.

See details on the [C++ and Java API](#cipherpack_apidoc) including its different C++ API level modules.

### Status
Build and clang-tidy clean on C++20, passing all unit tests.

## Supported Platforms
Language requirements
- C++20 or better, see [jaulib C++ Minimum Requirements](https://jausoft.com/cgit/jaulib.git/about/README.md#cpp_min_req).
- Java 11, 17+ (optional)

See [supported platforms](PLATFORMS.md) for details.

### C++ Minimum Requirements
C++20 is the minimum requirement for releases > 1.1.4,
see [jaulib C++ Minimum Requirements](https://jausoft.com/cgit/jaulib.git/about/README.md#cpp_min_req).

Release 1.1.4 is the last version conforming to C++17.

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
- CMake >= 3.21 (2021-07-14)
- C++ compiler
  - gcc >= 11 (C++20), recommended >= 12
  - clang >= 13 (C++20), recommended >= 16
- Optional for `lint` validation
  - clang-tidy >= 16
- Optional for `vscodium` integration
  - clangd >= 16
  - clang-tools >= 16
  - clang-format >= 16
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

Installing build dependencies for Debian >= 12 and Ubuntu >= 22:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
apt install git
apt install build-essential g++ gcc libc-dev libpthread-stubs0-dev 
apt install clang-16 clang-tidy-16 clangd-16 clang-tools-16 clang-format-16
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

#### Build preparations

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
git clone --recurse-submodule git://jausoft.com/srv/scm/cipherpack.git
cd cipherpack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

<a name="cmake_presets_optional"></a>

#### CMake Build via Presets
Analog to [jaulib CMake build presets](https://jausoft.com/cgit/jaulib.git/about/README.md#cmake_presets_optional) ...

Following debug presets are defined in `CMakePresets.json`
- `debug`
  - default generator
  - default compiler
  - C++20
  - debug enabled
  - java (if available)
  - libunwind enabled
  - libcurl enabled
  - testing on
  - testing with sudo off
- `debug-gcc`
  - inherits from `debug`
  - compiler: `gcc`
  - disabled `clang-tidy`
- `debug-clang`
  - inherits from `debug`
  - compiler: `clang`
  - enabled `clang-tidy`
- `release`
  - inherits from `debug`
  - debug disabled
  - libunwind disabled
- `release-gcc`
  - compiler: `gcc`
  - disabled `clang-tidy`
- `release-clang`
  - compiler: `clang`
  - enabled `clang-tidy`

Kick-off the workflow by e.g. using preset `release-gcc` to configure, build, test, install and building documentation.
You may skip `install` and `doc` by dropping it from `--target`.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
cmake --preset release-gcc
cmake --build --preset release-gcc --parallel
cmake --build --preset release-gcc --target test install doc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

<a name="cmake_presets_hardcoded"></a>

#### CMake Build via Hardcoded Presets
Analog to [jaulib CMake hardcoded presets](https://jausoft.com/cgit/jaulib.git/about/README.md#cmake_presets_hardcoded) ...

Besides above `CMakePresets.json` presets, 
`JaulibSetup.cmake` contains hardcoded presets for *undefined variables* if
- `CMAKE_INSTALL_PREFIX` and `CMAKE_CXX_CLANG_TIDY` cmake variables are unset, or 
- `JAU_CMAKE_ENFORCE_PRESETS` cmake- or environment-variable is set to `TRUE` or `ON`

The hardcoded presets resemble `debug-clang` [presets](README.md#cmake_presets_optional).

Kick-off the workflow to configure, build, test, install and building documentation.
You may skip `install` and `doc` by dropping it from `--target`.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{.sh}
rm -rf build/default
cmake -B build/default
cmake --build build/default --parallel
cmake --build build/default --target test install doc
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The install target of the last command will create the include/ and lib/ directories with a copy of
the headers and library objects respectively in your dist location.

#### CMake Variables
Our cmake configure has a number of options, *cmake-gui* or *ccmake* can show
you all the options. The interesting ones are detailed below:

See [jaulib CMake variables](https://jausoft.com/cgit/jaulib.git/about/README.md#cmake_variables) for details.

#### Deprecated Build Scripts
- `scripts/build-cross.sh` .. [cross-build](#cross-build)
- `scripts/rebuild-cross.sh` .. [cross-build](#cross-build)

(*FIXME: scripts needs to be overhauled to reflect new CMake build/dist folder*)

### Test Scripts
- `scripts/test_java.sh` .. invoke a java unit test
- `scripts/test_exe_template.sh` .. invoke the symlink'ed files to invoke native unit tests

(*FIXME: scripts needs to be overhauled to reflect new CMake build/dist folder*)

### Cross Build
Also provided is a [cross-build script](https://jausoft.com/cgit/direct_bt.git/tree/scripts/build-cross.sh)
using chroot into a target system using [QEMU User space emulation](https://qemu-project.gitlab.io/qemu/user/main.html)
and [Linux kernel binfmt_misc](https://wiki.debian.org/QemuUserEmulation)
to run on other architectures than the host.

You may use [our pi-gen branch](https://jausoft.com/cgit/pi-gen.git/about/) to produce 
a Raspi-arm64, Raspi-armhf or PC-amd64 target image.

## IDE Integration

### Eclipse 
Tested Eclipse 2024-03 (4.31).

IDE integration configuration files are provided for 
- [Eclipse](https://download.eclipse.org/eclipse/downloads/) with extensions
  - [CDT](https://github.com/eclipse-cdt/) or [CDT @ eclipse.org](https://projects.eclipse.org/projects/tools.cdt)
  - [CDT-LSP](https://github.com/eclipse-cdt/cdt-lsp) *recommended*
    - Should work with clang toolchain >= 16
    - Utilizes clangd, clang-tidy and clang-format to support C++20 and above
    - Add to available software site: `https://download.eclipse.org/tools/cdt/releases/cdt-lsp-latest`
    - Install `C/C++ LSP Support` in the `Eclipse CDT LSP Category`
  - `CMake Support`, install `C/C++ CMake Build Support` with ID `org.eclipse.cdt.cmake.feature.group`
    - Usable via via [Hardcoded CMake Presets](README.md#cmake_presets_hardcoded) with `debug-clang`

The [Hardcoded CMake Presets](README.md#cmake_presets_hardcoded) will 
use `build/default` as the default build folder with debug enabled.

Make sure to set the environment variable `CMAKE_BUILD_PARALLEL_LEVEL`
to a suitable high number, best to your CPU core count.
This will enable parallel build with the IDE.

You can import the project to your workspace via `File . Import...` and `Existing Projects into Workspace` menu item.

For Eclipse one might need to adjust some setting in the `.project` and `.cproject` (CDT) 
via Eclipse settings UI, but it should just work out of the box.

Otherwise recreate the Eclipse project by 
- delete `.project` and `.cproject` 
- `File . New . C/C++ Project` and `Empty or Existing CMake Project` while using this project folder.

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

**1.1.4**
* Last version conforming to C++17

**1.1.1**
* Stable stream handling w/o knowledge of content-size under heavy load
* jaulib v1.1.1
  - Fixed `Java_org_jau_sys_Clock_get[Monotonic|WallClock]TimeImpl()` for JNI callbacks
  - Fixed `jau::io::ByteInStream_[URL|Feed]` utilize blocking read-operations w/o knowledge of content-size

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

