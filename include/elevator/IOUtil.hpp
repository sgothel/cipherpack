/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2020 ZAFENA AB
 */

#ifndef IOUTIL_HPP_
#define IOUTIL_HPP_

#include <string>
#include <cstdint>
#include <functional>

#include <jau/basic_types.hpp>
#include <jau/ringbuffer.hpp>

#include <botan_all.h>

namespace elevator {

class IOUtil {
    public:
        static bool file_exists(const std::string& name) noexcept;
        static bool remove(const std::string& fname) noexcept;

        typedef std::function<void (Botan::secure_vector<uint8_t>& /* data */, bool /* is_final */)> StreamConsumerFunc;

        typedef jau::ringbuffer<uint8_t, uint8_t, size_t> ByteRingbuffer;

        /**
         * Operation result value
         */
        enum class result_t : int8_t {
            /** Operation failed. */
            FAILED  = -1,

            /** Operation still in progress. */
            NONE    =  0,

            /** Operation succeeded. */
            SUCCESS =  1
        };
        typedef jau::ordered_atomic<result_t, std::memory_order::memory_order_relaxed> relaxed_atomic_result_t;

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

        /**
         *
         * @param url
         * @param buffer
         * @param consumer_fn
         * @return total bytes read or -1 if error
         */
        static ssize_t read_http_get(const std::string& url, Botan::secure_vector<uint8_t>& buffer,
                                     StreamConsumerFunc consumer_fn);

        static const size_t BEST_HTTP_RINGBUFFER_SIZE;

        /**
         * Asynchronous http read content using a byte jau::ringbuffer,
         * allowing parallel reading.
         *
         * @param url the URL of the content to read
         * @param buffer the ringbuffer destination to write into
         * @param content_length tracking the content_length
         * @param total_read tracking the total_read
         * @param result tracking the result_t
         */
        static void read_http_get(const std::string& url, ByteRingbuffer& buffer,
                                  jau::relaxed_atomic_ssize_t& content_length,
                                  jau::relaxed_atomic_ssize_t& total_read,
                                  relaxed_atomic_result_t& result) noexcept;

        /**
         * Asynchronous http read content using a byte jau::ringbuffer,
         * allowing parallel reading.
         *
         * @param url the URL of the content to read
         * @param buffer the ringbuffer destination to write into
         * @param result tracking the result_t
         */
        static void read_http_get(const std::string& url, ByteRingbuffer& buffer,
                                  relaxed_atomic_result_t& result) noexcept;

        static void print_stats(const std::string &prefix, const uint64_t out_bytes_total, uint64_t td_ms) noexcept;
};

} // namespace elevator

#endif /* IOUTIL_HPP_ */
