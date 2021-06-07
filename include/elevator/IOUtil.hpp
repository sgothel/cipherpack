/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#ifndef IOUTIL_HPP_
#define IOUtil_HPP_

#include <string>
#include <cstdint>

#include <jau/basic_types.hpp>

#include <botan_all.h>

namespace elevator {

class IOUtil {
    public:
        static bool file_exists(const std::string& name);
        static bool remove(const std::string& fname);

        typedef std::function<void (Botan::secure_vector<uint8_t>& /* data */, bool /* is_final */)> StreamConsumerFunc;

        /**
         *
         * @param input_file
         * @param buf_size
         * @param consumer_fn
         * @return total bytes read or -1 if error
         */
        static ssize_t read_file(const std::string& input_file, Botan::secure_vector<uint8_t>& buffer,
                                 StreamConsumerFunc consumer_fn);

        /**
         *
         * @param in
         * @param buf_size
         * @param consumer_fn
         * @return total bytes read or -1 if error
         */
        static ssize_t read_stream(std::istream& in, Botan::secure_vector<uint8_t>& buffer,
                                   StreamConsumerFunc consumer_fn);

        /**
         * @param in
         * @param buf_size
         * @param consumer_fn
         * @return total bytes read or -1 if error
         */
        static ssize_t read_stream(Botan::DataSource& in, Botan::secure_vector<uint8_t>& buffer,
                                   StreamConsumerFunc consumer_fn);

        static ssize_t read_http_get(const std::string& url, Botan::secure_vector<uint8_t>& buffer,
                                     StreamConsumerFunc consumer_fn);

        static void print_stats(const std::string &prefix, const uint64_t out_bytes_total, uint64_t td_ms);
};

} // namespace elevator

#endif /* IOUTIL_HPP_ */
