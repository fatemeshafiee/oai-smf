//
// Created by f2shafie on 12/05/24.
//
#include <iostream>

#include <nghttp2/asio_http2_client.h>
#include <nlohmann/json.hpp>

using boost::asio::ip::tcp;

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::client;
using json = nlohmann::json;

void subscribe() {
  boost::system::error_code ec;
  boost::asio::io_service io_service;
  //  boost::asio::ip::tcp::endpoint locale;
  boost::asio::ip::tcp::endpoint locale(boost::asio::ip::tcp::v4(), 0);



  // connect to localhost:3000
  // http://oai-nwdaf-nbi-gateway/nnwdaf-eventssubscription/v1/subscriptions
  session sess(io_service, locale, "oai-nwdaf-nbi-gateway", "8000");
  //  sess.submit()
  sess.on_connect([&sess](tcp::resolver::iterator endpoint_it) {
    boost::system::error_code ec;
    // header

    json payload = {
        { "notificationURI", "http://192.168.70.1:8081/notification" },
        { "eventSubscriptions",
         { { { "event", "ABNORMAL_BEHAVIOUR" },
           { "excepRequs", { { { "excepId", "SUSPICION_OF_DDOS_ATTACK" } } } },
           { "notificationMethod", "PERIODIC" }, { "repetitionPeriod", 10 } } } }
    };

    std::string pstrig = to_string(payload);
    auto header = header_map();
    int size = 0;
    std::string location;


    std::cout << pstrig;

    auto req = sess.submit(ec, "POST", "http://oai-nwdaf-nbi-gateway:8000/nnwdaf-eventssubscription/v1/subscriptions", pstrig, header);

    req->on_response([](const response &res) {
      // print status code and response header fields.
      std::cerr << "HTTP/2 " << res.status_code() << std::endl;
      for (auto &kv: res.header()) {
        std::cerr << kv.first << ": " << kv.second.value << "\n";
      }
      std::cerr << std::endl;

      res.on_data([](const uint8_t *data, std::size_t len) {
        std::cerr.write(reinterpret_cast<const char *>(data), len);
        std::cerr << std::endl;
      });
    });

    req->on_close([&sess](uint32_t error_code) {

      std::cerr << "HTTP/ERR " << error_code << std::endl;
      // shutdown session after first request was done.
      sess.shutdown();
    });
  });

  sess.on_error([](const boost::system::error_code &ec) {
    std::cerr << "error: " << ec.message() << std::endl;
  });

  io_service.run();
}