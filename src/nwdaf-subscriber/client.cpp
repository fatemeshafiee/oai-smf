/*
* Added by: Fatemeh Shafiei Ardestani
* See Git history for complete list of changes.
*/
//
// Created by f2shafie on 12/05/24.
//
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <string>
#include <chrono>
#include <nghttp2/asio_http2_client.h>
#include <nlohmann/json.hpp>
#include <time.h>
#include "logger.hpp"
using boost::asio::ip::tcp;

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::client;
using json = nlohmann::json;
std::string get_current_time(int input) {
  auto now = std::chrono::system_clock::now();
  if (input >= 0) {
    now += std::chrono::minutes(input);
  }
  std::time_t now_time = std::chrono::system_clock::to_time_t(now);
  std::tm local_tm = *std::localtime(&now_time);
  std::ostringstream oss;
  oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
  return oss.str();
}
void subscribe() {
  boost::system::error_code ec;
  boost::asio::io_service io_service;

  //  boost::asio::ip::tcp::endpoint locale;
  boost::asio::ip::tcp::endpoint locale(boost::asio::ip::tcp::v4(), 0);

  std::string startT = get_current_time(-1);
  std::string endT = get_current_time(5);

  // connect to localhost:3000
  // http://oai-nwdaf-nbi-gateway/nnwdaf-eventssubscription/v1/subscriptions
  session sess(io_service, locale, "oai-nwdaf-nbi-gateway", "8000");
  //  sess.submit()
  sess.on_connect([&sess, startT, endT](tcp::resolver::iterator endpoint_it) {
    boost::system::error_code ec;
    // header

    json payload = {
        { "notificationURI",
         "http://192.168.70.1:8081/notification" },
        { "eventSubscriptions",
         { { { "event", "ABNORMAL_BEHAVIOUR" },
           { "excepRequs", { { { "excepId", "SUSPICION_OF_DDOS_ATTACK" }
                          }
                          }
           },
           { "notificationMethod", "PERIODIC"
           }, { "repetitionPeriod", 10
           }
         }
         }
        }
    };

    std::string pstrig = to_string(payload);
    auto header = header_map();
    int size = 0;
    std::string location;


    std::cout << pstrig;

    auto req = sess.submit(ec, "POST", "http://oai-nwdaf-nbi-gateway:8000/nnwdaf-eventssubscription/v1/subscriptions", pstrig, header);
    Logger::nwdaf_sub().warn("[DSN_Latency_SMF] The request for Abnormal behaviour sent to the NWDAF, the time is: {}", get_current_time(-1));
    req->on_response([](const response &res) {
      Logger::nwdaf_sub().warn("[DSN_Latency_SMF] The response for Abnormal behaviour request received, the time is: {}", get_current_time(-1));
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