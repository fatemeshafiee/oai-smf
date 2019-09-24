
#include "IndividualPDUSessionHSMFApi.h"
#include "IndividualSMContextApi.h"
#include "PDUSessionsCollectionApi.h"
#include "SMContextsCollectionApi.h"
#include "ApiConfiguration.h"
#include "ApiClient.h"
#include "nlohmann/json.hpp"

#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#define DEFAULT_JSON_FILE  "../inputs/SmContextCreateData.json"

using namespace utility;                    // Common utilities like string conversions
using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace concurrency::streams;       // Asynchronous streams                            // JSON library
using namespace oai::smf::api;
using namespace oai::smf::model;
//using json = nlohmann::json;
int main(int argc, char* argv[])
{

   // create ApiConfiguration
   std::shared_ptr <ApiConfiguration> apiConfiguration (new ApiConfiguration);
   apiConfiguration->setBaseUrl(utility::conversions::to_string_t("http://172.16.74.129:8080/msmf/v1"));

   std::shared_ptr <ApiClient> apiClient(new ApiClient (apiConfiguration));

   std::shared_ptr<SmContextMessage> smContextMessage (new SmContextMessage);
   //fill the content of smContextMessage
   //TODO:
   std::shared_ptr<SmContextCreateData> smContextCreateData (new SmContextCreateData);


   json::value     jv;                                          // JSON read from input file

   try {
          string_t        importFile = DEFAULT_JSON_FILE;           // extract filename
          ifstream_t      f(importFile);                              // filestream of working file
          stringstream_t  s;                                          // string stream for holding JSON read from file

          if (f) {
              s << f.rdbuf();                                         // stream results of reading from file stream into string stream
              f.close();                                              // close the filestream

              jv = json::value::parse(s);                                             // parse the resultant string stream.
              std::cout << "file" << DEFAULT_JSON_FILE<<std::endl;
          }
      }
      catch (web::json::json_exception excep) {
          std::cout << "ERROR Parsing JSON: ";
          std::cout << excep.what();
      }

      //auto supi = jv.at(U("supi"));
      //std::cout << supi <<std::endl;


   smContextCreateData->fromJson(jv);
   smContextMessage->setJsonData(smContextCreateData);
   std::shared_ptr<SMContextsCollectionApi> smContextsCollectionApi (new SMContextsCollectionApi (apiClient));
   smContextsCollectionApi->postSmContexts (smContextMessage);

   return 0;
}

