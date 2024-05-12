//
// Created by f2shafie on 12/05/24.
//
#include <iostream>

#include <nghttp2/asio_http2_server.h>

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;

void serve() {
  boost::system::error_code ec;
  http2 server;

  server.handle("/notification", [](const request &req, const response &res) {

    req.on_data([](const uint8_t *data, std::size_t len) {
      std::cout.write(reinterpret_cast<const char *>(data), len);
      std::cout << std::endl;
    });
    //    std::cout <<"this is a request body" << req.on_data()
    res.write_head(200);
    res.end("hello, world\n");
  });

  if (server.listen_and_serve(ec, "0.0.0.0", "3000")) {
    std::cerr << "error: " << ec.message() << std::endl;
  }
}