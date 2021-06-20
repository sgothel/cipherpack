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
        /**
         * Return the given timestamp as a timestring in format `YYYY-MM-DD HH:MM:SS`
         * @param timestamp_sec timestamp in seconds since Unix epoch
         * @param local if true, returns the time in local time, otherwise UTC
         */
        static std::string getTimestampString(const uint64_t timestamp_sec, const bool local) noexcept;

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

/**
* This class represents a Ringbuffer-Based Http DataSource
*/
class DataSource_Http final : public Botan::DataSource {
    public:
        size_t read(uint8_t out[], size_t length) override;
        size_t peek(uint8_t out[], size_t length, size_t peek_offset) const override;
        bool check_available(size_t n) override {
            return ( IOUtil::result_t::NONE == m_http_result && http_content_length - m_bytes_consumed >= n ) ||
                   ( IOUtil::result_t::SUCCESS == m_http_result && m_buffer.getSize() >= n );
        }
        bool end_of_data() const override { return IOUtil::result_t::NONE != m_http_result && m_buffer.isEmpty(); }

        std::string id() const override { return m_url; }

        /**
         * Construct a ringbuffer backed Http DataSource
         * @param url the URL of the data to read
         */
        DataSource_Http(const std::string& url);

        size_t get_bytes_read() const override { return m_bytes_consumed; }

    private:
        const std::string m_url;
        IOUtil::ByteRingbuffer m_buffer;
        jau::relaxed_atomic_ssize_t http_content_length;
        jau::relaxed_atomic_ssize_t http_total_bytes;
        IOUtil::relaxed_atomic_result_t m_http_result;
        size_t m_bytes_consumed;
};

/**
* This class represents a wrapped DataSource with the capability
* to record the byte stream read out at will.
* <p>
* Peek'ed bytes won't be recorded, only read bytes.
* </p>
*/
class DataSource_Recorder final : public Botan::DataSource {
    public:
        size_t read(uint8_t[], size_t) override;

        size_t peek(uint8_t out[], size_t length, size_t peek_offset) const override {
            return m_parent.peek(out, length, peek_offset);
        }

        bool check_available(size_t n) override {
            return m_parent.check_available(n);
        }

        bool end_of_data() const override {
            return m_parent.end_of_data();
        }

        std::string id() const override { return m_parent.id(); }

        /**
         * Construct a DataSource wrapper using the given parent DataSource,
         * i.e. the actual DataSource.
         * @param parent the actual parent DataSource origin
         * @param buffer a user defined buffer for the recording
         */
        DataSource_Recorder(Botan::DataSource& parent, Botan::secure_vector<uint8_t>& buffer)
        : m_parent(parent), m_buffer(buffer), m_rec_offset(0), m_is_recording(false) {};

        DataSource_Recorder(const DataSource_Recorder&) = delete;

        DataSource_Recorder& operator=(const DataSource_Recorder&) = delete;

        ~DataSource_Recorder() {}

        size_t get_bytes_read() const override { return m_parent.get_bytes_read(); }

        /**
         * Starts the recording.
         * <p>
         * A potential previous recording will be cleared.
         * </p>
         */
        void start_recording() noexcept;

        /**
         * Stops the recording.
         * <p>
         * The recording persists.
         * </p>
         */
        void stop_recording() noexcept;

        /**
         * Clears the recording.
         * <p>
         * If the recording was ongoing, also stops the recording.
         * </p>
         */
        void clear_recording() noexcept;

        /** Returns the reference of the recording buffer given by user. */
        Botan::secure_vector<uint8_t>& get_recording() noexcept { return m_buffer; }

        size_t get_bytes_recorded() noexcept { return m_buffer.size(); }

        /** Returns the recording start position. */
        size_t get_recording_start_pos() noexcept { return m_rec_offset; }

        bool is_recording() noexcept { return m_is_recording; }

    private:
        Botan::DataSource& m_parent;
        Botan::secure_vector<uint8_t>& m_buffer;
        size_t m_rec_offset;
        bool m_is_recording;
};


} // namespace elevator

#endif /* IOUTIL_HPP_ */
