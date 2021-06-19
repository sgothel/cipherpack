#include "test_data.hpp"

const std::string TestData::enc_pub_key_fname = "../../../keys/terminal_rsa.pub.pem";
const std::string TestData::dec_sec_key_fname = "../../../keys/terminal_rsa";
const std::string TestData::dec_sec_key_passphrase = "";
const std::string TestData::sign_pub_key_fname = "../../../keys/host_rsa.pub.pem";
const std::string TestData::sign_sec_key_fname = "../../../keys/host_rsa";
const std::string TestData::sign_sec_key_passphrase = "";

const std::string TestData::url_input_root = "http://jordan/deployment/elevator/";
const std::string TestData::basename_64kB = "data-64kB.bin"; // + '.enc' for encrypted
const std::string TestData::basename_382MB = "data-382MB.mkv"; // + '.enc' for encrypted
const std::string TestData::basename_1GB = "data-1GB.mkv"; // + '.enc' for encrypted
