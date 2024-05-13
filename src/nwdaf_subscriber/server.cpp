#include <iostream>
#include <nlohmann/json.hpp>
#include <nghttp2/asio_http2_server.h>

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;

using json = nlohmann::json;
//std::string jsonData;

void serve() {
  boost::system::error_code ec;
  http2 server;

  server.handle("/notification", [](const request &req, const response &res) {



    req.on_data([](const uint8_t *data, std::size_t len) {
      if (len == 0 || !data) {
        return;
      }

      std::string jsonData(reinterpret_cast<const char*>(data));
      struct UEPduRatioPair {
        std::string ueIP;
        int pduSessId;
        double ratio;
      };
      std::vector<UEPduRatioPair> ueRatioList;
      std::cout <<"The Json data is:"<<jsonData<< std::endl;

      json jsonObj = json::parse(jsonData);

      if (jsonObj.contains("abnorBehavrs")) {

        std::cout << "The JSON contains an array named 'ddos_entries'." << std::endl;
        // Access the "ddos_entries" array
        auto  abnorBehavrs= jsonObj["abnorBehavrs"];



        // Iterate over the array and print the values
        for (const auto& abnorBehavr : abnorBehavrs) {
          // Access the "ddos_entries" array
          auto ddosEntries = abnorBehavr["ddos_entries"];

          // Iterate over the "ddos_entries" array
          for (const auto& entry : ddosEntries) {
            // std::cout << "pdu_sess_id: " << entry["pdu_sess_id"] << std::endl;
            UEPduRatioPair pair;
            pair.ueIP = entry["ue_ip"];
            pair.pduSessId = 0;        //entry["pdu_sess_id"];
            pair.ratio = entry["ratio"];

            ueRatioList.push_back(pair);
            std::cout << "UE IP: " << pair.ueIP << std::endl;
            std::cout << "PDU session ID: " << pair.pduSessId << std::endl;
            std::cout << "Ratio: " << pair.ratio << std::endl;
            std::cout << std::endl;

          }
        }
      }



    });

    //    std::cout <<"this is a request body" << req.on_data()
    res.write_head(200);
    res.end("hello, world\n");
  });

  if (server.listen_and_serve(ec, "0.0.0.0", "3000")) {
    std::cerr << "error: " << ec.message() << std::endl;
  }
}