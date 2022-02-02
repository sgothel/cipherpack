/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2021 Gothel Software e.K.
 * Copyright (c) 2021 ZAFENA AB
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

#include "test_data.hpp"

const std::string TestData::enc_pub_key_fname = "../../../keys/terminal_rsa.pub.pem";
const std::string TestData::dec_sec_key_fname = "../../../keys/terminal_rsa";
const std::string TestData::dec_sec_key_passphrase = "";
const std::string TestData::sign_pub_key_fname = "../../../keys/host_rsa.pub.pem";
const std::string TestData::sign_sec_key_fname = "../../../keys/host_rsa";
const std::string TestData::sign_sec_key_passphrase = "";

const std::string TestData::url_input_root = "http://localhost:8080/test_data/";
const std::string TestData::basename_64kB = "data-64kB.bin"; // + '.enc' for encrypted
const std::string TestData::basename_382MB = "data-382MB.mkv"; // + '.enc' for encrypted
const std::string TestData::basename_1GB = "data-1GB.mkv"; // + '.enc' for encrypted
