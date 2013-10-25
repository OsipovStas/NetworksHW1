/* 
 * File:   main.cpp
 * Author: stasstels
 *
 * Created on October 25, 2013, 4:39 PM
 */

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <istream>
#include <iostream>
#include <ostream>

using boost::asio::ip::icmp;
using boost::asio::deadline_timer;
namespace posix_time = boost::posix_time;

#include "../Core/icmp_header.h"
#include "../Core/ipv4_header.h"

class client {
public:

    client(boost::asio::io_service& io_service, const char* dest) :
    socket_(io_service, icmp::v4()),
    resolver_(io_service),
    timer_(io_service),
    num_replies_(0) {
        icmp::resolver::query query(icmp::v4(), dest, "");
        destination_ = *resolver_.resolve(query);

        start_send();
        start_receive();
    }

    void start_send() {
        std::string ipStr("192.168.54.11");
        ulong adr = boost::asio::ip::address_v4::from_string(ipStr.c_str()).to_ulong();

        // Create an ICMP header for an echo request.
        icmp_header mask_request;
        mask_request.type(icmp_header::address_request);
        mask_request.code(0);
        mask_request.identifier(0);
        mask_request.sequence_number(0);
        compute_checksum(mask_request, ipStr.begin(), ipStr.end());

        // Encode the request packet.
        boost::asio::streambuf request_buffer;
        std::ostream os(&request_buffer);
        os << mask_request << adr;

        // Send the request.
        time_sent_ = posix_time::microsec_clock::universal_time();
        socket_.send_to(request_buffer.data(), destination_);

        // Wait up to five seconds for a reply.
        num_replies_ = 0;
        timer_.expires_at(time_sent_ + posix_time::seconds(5));
        timer_.async_wait(boost::bind(&client::handle_timeout, this));
    }

    void handle_timeout() {
        if (num_replies_ == 0) {
            std::cout << "Request timed out" << std::endl;

            timer_.expires_at(time_sent_ + posix_time::seconds(1));
            timer_.async_wait(boost::bind(&client::start_send, this));
        }
    }

    void start_receive() {
        // Discard any data already in the buffer.
        reply_buffer_.consume(reply_buffer_.size());

        // Wait for a reply. We prepare the buffer to receive up to 64KB.
        socket_.async_receive(reply_buffer_.prepare(65536),
                boost::bind(&client::handle_receive, this, _2));
    }

    void handle_receive(size_t length) {
        // The actual number of bytes received is committed to the buffer so that we
        // can extract it using a std::istream object.
        reply_buffer_.commit(length);

        // Decode the reply packet.
        std::istream is(&reply_buffer_);
        ipv4_header ipv4_hdr;
        icmp_header icmp_hdr;
        u_int32_t mask;
        is >> ipv4_hdr >> icmp_hdr >> mask;

        // We can receive all ICMP packets received by the host, so we need to
        // filter out only the echo replies that match the our identifier and
        // expected sequence number.
        if (is && icmp_hdr.type() == icmp_header::address_reply) {
            // If this is the first reply, interrupt the five second timeout.
            if (num_replies_++ == 0)
                timer_.cancel();

            // Print out some information about the reply packet.
            std::cout << length - ipv4_hdr.header_length()
                    << " bytes from " << ipv4_hdr.source_address()
                    << ": icmp_seq=" << icmp_hdr.sequence_number()
                    << ", ttl = " << ipv4_hdr.time_to_live()
                    << ", mask = " << boost::asio::ip::address_v4(mask)
                    << std::endl;
            return;
        } 
        start_receive();
    }

private:
    icmp::socket socket_;
    deadline_timer timer_;
    icmp::resolver resolver_;
    posix_time::ptime time_sent_;
    boost::asio::streambuf reply_buffer_;
    std::size_t num_replies_;
    icmp::endpoint destination_;
};

int main(int argc, char* argv[]) {
    try {
        if (argc != 2) {
            std::cerr << "Usage: client <host>" << std::endl;
            return 1;
        }

        boost::asio::io_service io_service;
        client c(io_service, argv[1]);
        io_service.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}

