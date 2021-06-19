/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
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
        static const std::string enc_pub_key_fname;
        static const std::string dec_sec_key_fname;
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
