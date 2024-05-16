#include <iostream>
#include <nlohmann/json.hpp>
#include <nghttp2/asio_http2_server.h>
#include "mitigate_attack.h"
#include "client.h"
#include "smf_app.hpp"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;

using json = nlohmann::json;

void serve() {
  boost::system::error_code ec;
  http2 server;
server.handle("/subscribe", [](const request &req, const response &res) {
    subscribe();
    res.write_head(200);
    res.end("Subscribed!\n");
    Logger::nwdaf_sub().warn("[FATEMEH] The subscription triggerred!");
});
  server.handle("/notification", [](const request &req, const response &res) {

    req.on_data([](const uint8_t *data, std::size_t len) {
      if (len == 0 || !data) {
        return;
      }

      std::string jsonData(reinterpret_cast<const char*>(data), len);

      std::vector<UEPduRatioPair> ueRatioList;
      Logger::nwdaf_sub().warn("The Json data is: %s", jsonData);


      json jsonObj = json::parse(jsonData);

      if (jsonObj.contains("abnorBehavrs")) {
        Logger::nwdaf_sub().warn("The JSON contains an array named 'ddos_entries'.");
//        std::cout << "The JSON contains an array named 'ddos_entries'." << std::endl;
        auto  abnorBehavrs= jsonObj["abnorBehavrs"];
        for (const auto& abnorBehavr : abnorBehavrs) {
          // Access the "ddos_entries" array
          auto ddosEntries = abnorBehavr["ddos_entries"];
          for (const auto& entry : ddosEntries) {
            UEPduRatioPair pair;
            pair.ueIP = entry["ue_ip"];
            pair.pduSessId = entry["pdu_sess_id"];
            pair.seId = entry["seid"];
            pair.ratio = entry["ratio"];
            ueRatioList.push_back(pair);
//            std::cout << "UE IP: " << pair.ueIP << std::endl;
//            std::cout << "PDU session ID: " << pair.pduSessId << std::endl;
//            std::cout << "Ratio: " << pair.ratio << std::endl;
//            std::cout << std::endl;

          }
          //Logger::smf_app().warn("[FATEMEH] The subscription triggerred!",ueRatioList[0]);
          Logger::nwdaf_sub().warn("[FATEMEH] Calling the manage function!");
          manage_suspicious_session(ueRatioList);
        }}
    });

    //    std::cout <<"this is a request body" << req.on_data()
    res.write_head(200);
    res.end("hello, world\n");
  });

  if (server.listen_and_serve(ec, "0.0.0.0", "3000")) {
    std::cerr << "error: " << ec.message() << std::endl;
  }
}