/*
* Added by: Fatemeh Shafiei Ardestani
* See Git history for complete list of changes.
 */
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
      Logger::nwdaf_sub().warn("[DSN_Latency_SMF] The notification for Abnormal behaviour request received, the time is: {}", get_current_time(-1));

      std::string jsonData(reinterpret_cast<const char*>(data), len);

      std::vector<UEPduRatioPair> ueRatioList;
      Logger::nwdaf_sub().warn("[DSN_Latency_SMF] The Json data is: %s", jsonData);


      json jsonObj = json::parse(jsonData);

      if (jsonObj.contains("abnorBehavrs")) {
        Logger::nwdaf_sub().warn("The JSON contains an array named abnorBehavrs.");
        auto  abnorBehavrs= jsonObj["abnorBehavrs"];
        for (const auto& abnorBehavr : abnorBehavrs) {
          if (abnorBehavr.contains("ddos_entries")) {
            auto ddosEntries = abnorBehavr["ddos_entries"];
            for (const auto& entry : ddosEntries) {
              UEPduRatioPair pair;
              pair.ueIP = entry["ue_ip"];
              pair.seId = entry["seid"];
              ueRatioList.push_back(pair);}

            Logger::nwdaf_sub().warn(
                "[DSN_Latency_SMF] Calling the manage function to mitigate the risk! the time is: {}",
                get_current_time(-1));
            manage_suspicious_session(ueRatioList);
          }
        }
      }
      
    });


    res.write_head(200);
    res.end("hello, world\n");
  });

  if (server.listen_and_serve(ec, "0.0.0.0", "3000")) {
    std::cerr << "error: " << ec.message() << std::endl;
  }
}