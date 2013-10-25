/* 
 * File:   main.cpp
 * Author: stasstels
 *
 * Created on October 25, 2013, 6:50 PM
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

class server {
public:

    server(boost::asio::io_service & io_service) :
    io_service_(io_service),
    socket_(io_service, icmp::v4()),
    resolver_(io_service) {
        start_receive();
    }

private:

    void start_receive() {
        // Discard any data already in the buffer.
        reply_buffer_.consume(reply_buffer_.size());

        // Wait for a reply. We prepare the buffer to receive up to 64KB.
        socket_.async_receive(reply_buffer_.prepare(65536),
                boost::bind(&server::handle_receive, this, _2));
    }

    void handle_receive(size_t length) {
        // The actual number of bytes received is committed to the buffer so that we
        // can extract it using a std::istream object.
        reply_buffer_.commit(length);

        // Decode the reply packet.
        std::istream is(&reply_buffer_);
        ipv4_header ipv4_hdr;
        icmp_header icmp_hdr;
        u_long ip;
        is >> ipv4_hdr >> icmp_hdr;

        // We can receive all ICMP packets received by the host, so we need to
        // filter out only the echo replies that match the our identifier and
        // expected sequence number.
        if (is && icmp_hdr.type() == icmp_header::address_request) {
            is >> ip;

            // Print out some information about the reply packet.
            std::cout << length - ipv4_hdr.header_length()
                    << " bytes from " << ipv4_hdr.source_address()
                    << ": icmp_seq=" << icmp_hdr.sequence_number()
                    << ", ttl = " << ipv4_hdr.time_to_live()
                    << ", ip = " << boost::asio::ip::address_v4(ip)
                    << std::endl;
            send_reply(ipv4_hdr.source_address());
        }
        start_receive();
    }

    void send_reply(const boost::asio::ip::address_v4& address) {
        icmp::resolver::query query(icmp::v4(), address.to_string(), "");
        icmp::endpoint destination = *resolver_.resolve(query);


        std::string maskStr("255.255.255.0");
        ulong mask = boost::asio::ip::address_v4::from_string(maskStr.c_str()).to_ulong();

        // Create an ICMP header for an echo request.
        icmp_header mask_request;
        mask_request.type(icmp_header::address_reply);
        mask_request.code(0);
        mask_request.identifier(0);
        mask_request.sequence_number(0);
        compute_checksum(mask_request, maskStr.begin(), maskStr.end());

        // Encode the request packet.
        boost::asio::streambuf request_buffer;
        std::ostream os(&request_buffer);
        os << mask_request << mask;

        socket_.send_to(request_buffer.data(), destination);
    }

    boost::asio::io_service& io_service_;
    icmp::socket socket_;
    icmp::resolver resolver_;
    boost::asio::streambuf reply_buffer_;
};

int main(int argc, char* argv[]) {
    try {
        boost::asio::io_service io_service;
        server s(io_service);
        io_service.run();
    } catch (std::exception & e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}

