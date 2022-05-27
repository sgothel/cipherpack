/*
 * Author: Sven Gothel <sgothel@jausoft.com>
 * Copyright (c) 2021 Gothel Software e.K.
 * Copyright (c) 1999-2007 Jack Lloyd (Botan)
 * Copyright (c) 2005 Matthew Gregan (Botan)
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

#ifndef JAU_DATA_SOURCE_HPP_
#define JAU_DATA_SOURCE_HPP_

#include <fstream>
#include <string>
#include <cstdint>
#include <functional>
#include <thread>

#include <jau/basic_types.hpp>
#include <jau/ringbuffer.hpp>

#include <botan_all.h>

namespace elevator::io {

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

    typedef jau::ringbuffer<uint8_t, size_t> ByteRingbuffer;

    extern const size_t BEST_URLSTREAM_RINGBUFFER_SIZE;

    /**
    * This class represents a closeable DataSource
    */
    class DataSource_Closeable : public Botan::DataSource {
        public:
            /**
             * Close the stream if supported by the underlying mechanism.
             */
            virtual void close() noexcept = 0;

            ~DataSource_Closeable() override = default;

            virtual std::string to_string() const = 0;
    };

    /**
    * This class represents a secure Memory-Based DataSource
    */
    class DataSource_SecMemory final : public DataSource_Closeable {
       public:
          /**
           * Read from a memory buffer
           */
          size_t read(uint8_t[], size_t) override;

          /**
           * Peek into a memory buffer
           */
          size_t peek(uint8_t[], size_t, size_t) const override;

          bool check_available(size_t n) override;

          /**
           * Check if the memory buffer is empty
           */
          bool end_of_data() const override;

          /**
          * Construct a memory source that reads from a string
          * @param in the string to read from
          */
          explicit DataSource_SecMemory(const std::string& in);

          /**
          * Construct a memory source that reads from a byte array
          * @param in the byte array to read from
          * @param length the length of the byte array
          */
          DataSource_SecMemory(const uint8_t in[], size_t length)
          : m_source(in, in + length), m_offset(0) {}

          /**
          * Construct a memory source that reads from a secure_vector
          * @param in the MemoryRegion to read from
          */
          explicit DataSource_SecMemory(const Botan::secure_vector<uint8_t>& in)
          : m_source(in), m_offset(0) {}

          /**
          * Construct a memory source that reads from a std::vector
          * @param in the MemoryRegion to read from
          */
          explicit DataSource_SecMemory(const std::vector<uint8_t>& in)
          : m_source(in.begin(), in.end()), m_offset(0) {}

          void close() noexcept override;

          ~DataSource_SecMemory() override { close(); }

          size_t get_bytes_read() const override { return m_offset; }

          std::string to_string() const override;

       private:
          Botan::secure_vector<uint8_t> m_source;
          size_t m_offset;
    };

    /**
    * This class represents an std::istream based DataSource.
    */
    class DataSource_Stream final : public DataSource_Closeable {
       public:
          size_t read(uint8_t[], size_t) override;
          size_t peek(uint8_t[], size_t, size_t) const override;
          bool check_available(size_t n) override;
          bool end_of_data() const override;
          std::string id() const override;

          DataSource_Stream(std::istream&, const std::string& id = "<std::istream>");

          DataSource_Stream(const DataSource_Stream&) = delete;

          DataSource_Stream& operator=(const DataSource_Stream&) = delete;

          void close() noexcept override;

          ~DataSource_Stream() override { close(); }

          size_t get_bytes_read() const override { return m_bytes_consumed; }

          std::string to_string() const override;

       private:
          const std::string m_identifier;

          std::istream& m_source;
          size_t m_bytes_consumed;
    };


    /**
    * This class represents a file based DataSource.
    */
    class DataSource_File final : public DataSource_Closeable {
       public:
          size_t read(uint8_t[], size_t) override;
          size_t peek(uint8_t[], size_t, size_t) const override;
          bool check_available(size_t n) override { return m_content_size >= (uint64_t)n; };
          bool end_of_data() const override;
          std::string id() const override;

          /**
          * Construct a Stream-Based DataSource from filesystem path
          * @param file the path to the file
          * @param use_binary whether to treat the file as binary or not
          */
          DataSource_File(const std::string& file, bool use_binary = false);

          DataSource_File(const DataSource_File&) = delete;

          DataSource_File& operator=(const DataSource_File&) = delete;

          void close() noexcept override;

          ~DataSource_File() override { close(); }

          size_t get_bytes_read() const override { return (size_t)m_bytes_consumed; }

          /**
           * Botan's get_bytes_read() API uses `size_t`,
           * which only covers 32bit or 4GB on 32bit systems.
           * @return uint64_t bytes read
           */
          uint64_t get_bytes_read_u64() const { return m_bytes_consumed; }

          std::string to_string() const override;

       private:
          const std::string m_identifier;
          std::unique_ptr<std::ifstream> m_source;
          uint64_t m_content_size;
          uint64_t m_bytes_consumed;
    };

    /**
    * This class represents a Ringbuffer-Based URL DataSource
    */
    class DataSource_URL final : public DataSource_Closeable {
        public:
            /**
             * Check whether n bytes are available in the input stream.
             *
             * Wait up to timeout duration given in constructor until n bytes become available, where fractions_i64::zero waits infinitely.
             *
             * This method is blocking.
             *
             * @param n byte count to wait for
             * @return true if n bytes are available, otherwise false
             */
            bool check_available(size_t n) override;

            /**
             * Read from the source. Moves the internal offset so that every
             * call to read will return a new portion of the source.
             *
             * Method only blocks until at least one byte is available, using timeout duration given in constructor.
             * To require a specific number of bytes, call blocking check_available() first.
             *
             * @param out the byte array to write the result to
             * @param length the length of the byte array out
             * @return length in bytes that was actually read and put into out
             */
            size_t read(uint8_t out[], size_t length) override;

            size_t peek(uint8_t out[], size_t length, size_t peek_offset) const override;

            bool end_of_data() const override;

            std::string id() const override { return m_url; }

            /**
             * Construct a ringbuffer backed Http DataSource
             * @param url the URL of the data to read
             * @param timeout maximum duration in fractions of seconds to wait @ check_available(), where fractions_i64::zero waits infinitely
             * @param exp_size if > 0 it is additionally used to determine EOF, otherwise the underlying EOF mechanism is being used only (default).
             */
            DataSource_URL(const std::string& url, jau::fraction_i64 timeout, const uint64_t exp_size=0);

            DataSource_URL(const DataSource_URL&) = delete;

            DataSource_URL& operator=(const DataSource_URL&) = delete;

            void close() noexcept override;

            ~DataSource_URL() override { close(); }

            size_t get_bytes_read() const override { return (size_t)m_bytes_consumed; }

            /**
             * Botan's get_bytes_read() API uses `size_t`,
             * which only covers 32bit or 4GB on 32bit systems.
             * @return uint64_t bytes read
             */
            uint64_t get_bytes_read_u64() const { return m_bytes_consumed; }

            std::string to_string() const override;

        private:
            uint64_t get_available() const noexcept { return m_has_content_length ? m_content_size - m_bytes_consumed : 0; }
            std::string to_string_int() const;

            const std::string m_url;
            const uint64_t m_exp_size;
            jau::fraction_i64 m_timeout;
            ByteRingbuffer m_buffer;
            jau::relaxed_atomic_bool m_has_content_length; // informal only
            jau::relaxed_atomic_uint64 m_content_size; // informal only
            jau::relaxed_atomic_uint64 m_total_xfered;
            relaxed_atomic_result_t m_result;
            std::thread m_url_thread;
            uint64_t m_bytes_consumed;
    };

    /**
    * This class represents a Ringbuffer-Based externally provisioned data feed.
    */
    class DataSource_Feed final : public DataSource_Closeable {
        public:
            /**
             * Check whether n bytes are available in the input stream.
             *
             * Wait up to timeout duration given in constructor until n bytes become available, where fractions_i64::zero waits infinitely.
             *
             * This method is blocking.
             *
             * @param n byte count to wait for
             * @return true if n bytes are available, otherwise false
             */
            bool check_available(size_t n) override;

            /**
             * Read from the source. Moves the internal offset so that every
             * call to read will return a new portion of the source.
             *
             * Method only blocks until at least one byte is available, using timeout duration given in constructor.
             * To require a specific number of bytes, call blocking check_available() first.
             *
             * @param out the byte array to write the result to
             * @param length the length of the byte array out
             * @return length in bytes that was actually read and put into out
             */
            size_t read(uint8_t out[], size_t length) override;

            size_t peek(uint8_t out[], size_t length, size_t peek_offset) const override;

            bool end_of_data() const override;

            std::string id() const override { return m_id; }

            /**
             * Construct a ringbuffer backed externally provisioned DataSource
             * @param id_name arbitrary identifier for this instance
             * @param timeout maximum duration in fractions of seconds to wait @ check_available() and write(), where fractions_i64::zero waits infinitely
             * @param exp_size if > 0 it is additionally used to determine EOF, otherwise the underlying EOF mechanism is being used only (default).
             */
            DataSource_Feed(const std::string& id_name, jau::fraction_i64 timeout, const uint64_t exp_size=0);

            DataSource_Feed(const DataSource_URL&) = delete;

            DataSource_Feed& operator=(const DataSource_URL&) = delete;

            void close() noexcept override;

            ~DataSource_Feed() override { close(); }

            size_t get_bytes_read() const override { return m_bytes_consumed; }

            /**
             * Botan's get_bytes_read() API uses `size_t`,
             * which only covers 32bit or 4GB on 32bit systems.
             * @return uint64_t bytes read
             */
            uint64_t get_bytes_read_u64() const { return m_bytes_consumed; }

            /**
             * Write given bytes to the async ringbuffer.
             *
             * Wait up to timeout duration given in constructor until ringbuffer space is available, where fractions_i64::zero waits infinitely.
             *
             * This method is blocking.
             *
             * @param n byte count to wait for
             * @param in the byte array to transfer to the async ringbuffer
             * @param length the length of the byte array in
             */
            void write(uint8_t in[], size_t length);

            /**
             * Set known content size, informal only.
             * @param content_length the content size in bytes
             */
            void set_content_size(const uint64_t size) noexcept {
                m_content_size = size;
                m_has_content_length = true;
            }

            /**
             * Set end-of-data (EOS), i.e. when feeder completed provisioning bytes.
             *
             * @param result should be either result_t::FAILED or result_t::SUCCESS.
             */
            void set_eof(const result_t result) noexcept { m_result = result; }

            std::string to_string() const override;

        private:
            uint64_t get_available() const noexcept { return m_has_content_length ? m_content_size - m_bytes_consumed : 0; }
            std::string to_string_int() const;

            const std::string m_id;
            const uint64_t m_exp_size;
            jau::fraction_i64 m_timeout;
            ByteRingbuffer m_buffer;
            jau::relaxed_atomic_bool m_has_content_length; // informal only
            jau::relaxed_atomic_uint64 m_content_size; // informal only
            jau::relaxed_atomic_uint64 m_total_xfered;
            relaxed_atomic_result_t m_result;
            uint64_t m_bytes_consumed;
    };

    /**
    * This class represents a wrapped DataSource with the capability
    * to record the byte stream read out at will.
    * <p>
    * Peek'ed bytes won't be recorded, only read bytes.
    * </p>
    */
    class DataSource_Recorder final : public DataSource_Closeable {
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
            DataSource_Recorder(DataSource_Closeable& parent, Botan::secure_vector<uint8_t>& buffer)
            : m_parent(parent), m_bytes_consumed(0), m_buffer(buffer), m_rec_offset(0), m_is_recording(false) {};

            DataSource_Recorder(const DataSource_Recorder&) = delete;

            DataSource_Recorder& operator=(const DataSource_Recorder&) = delete;

            void close() noexcept override;

            ~DataSource_Recorder() override { close(); }

            size_t get_bytes_read() const override { return m_parent.get_bytes_read(); }

            /**
             * Botan's get_bytes_read() API uses `size_t`,
             * which only covers 32bit or 4GB on 32bit systems.
             * @return uint64_t bytes read
             */
            uint64_t get_bytes_read_u64() const { return m_bytes_consumed; }

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
            uint64_t get_recording_start_pos() noexcept { return m_rec_offset; }

            bool is_recording() noexcept { return m_is_recording; }

            std::string to_string() const override;

        private:
            DataSource_Closeable& m_parent;
            uint64_t m_bytes_consumed;
            Botan::secure_vector<uint8_t>& m_buffer;
            uint64_t m_rec_offset;
            bool m_is_recording;
    };

} // namespace elevator::io

#endif /* JAU_DATA_SOURCE_HPP_ */
