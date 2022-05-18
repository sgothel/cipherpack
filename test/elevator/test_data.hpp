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

#ifndef TEST_DATA_HPP_
#define TEST_DATA_HPP_

#include <iostream>
#include <cassert>
#include <cinttypes>
#include <cstring>

class TestData {
    public:
        static constexpr const bool overwrite = true;
        static const std::string enc_pub_key1_fname;
        static const std::string dec_sec_key1_fname;

        static const std::string enc_pub_key2_fname;
        static const std::string dec_sec_key2_fname;

        static const std::string enc_pub_key3_fname;
        static const std::string dec_sec_key3_fname;

        static const std::string dec_sec_key_passphrase;

        static const std::string sign_pub_key_fname;
        static const std::string sign_sec_key_fname;
        static const std::string sign_sec_key_passphrase;

        static const std::string url_input_root;
        static const std::string basename_64kB;
        static const std::string basename_382MB;
        static const std::string basename_1GB;
};

#endif /* TEST_DATA_HPP_ */
