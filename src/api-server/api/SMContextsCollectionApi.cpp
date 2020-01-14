/**
* Nsmf_PDUSession
* SMF PDU Session Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved. 
*
* The version of the OpenAPI document: 1.1.0.alpha-1
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/

#include "SMContextsCollectionApi.h"
#include "Helpers.h"

namespace oai {
namespace smf_server {
namespace api {

using namespace oai::smf_server::helpers;
using namespace oai::smf_server::model;

SMContextsCollectionApi::SMContextsCollectionApi(std::shared_ptr<Pistache::Rest::Router> rtr) { 
    router = rtr;
}

void SMContextsCollectionApi::init() {
    setupRoutes();
}

void SMContextsCollectionApi::setupRoutes() {
    using namespace Pistache::Rest;

    Routes::Post(*router, base + "/sm-contexts", Routes::bind(&SMContextsCollectionApi::post_sm_contexts_handler, this));

    // Default handler, called when a route is not found
    router->addCustomHandler(Routes::bind(&SMContextsCollectionApi::sm_contexts_collection_api_default_handler, this));
}

void SMContextsCollectionApi::post_sm_contexts_handler(const Pistache::Rest::Request &request, Pistache::Http::ResponseWriter response) {

    // Getting the body param
   
	std::cout <<"received a SM context create request" << request.body() <<std::endl;
	SmContextMessage smContextMessage;
    
    try {
      nlohmann::json::parse(request.body()).get_to(smContextMessage);
      this->post_sm_contexts(smContextMessage, response);
    } catch (nlohmann::detail::exception &e) {
        //send a 400 error
        response.send(Pistache::Http::Code::Bad_Request, e.what());
        return;
    } catch (std::exception &e) {
        //send a 500 error
        response.send(Pistache::Http::Code::Internal_Server_Error, e.what());
        return;
    }

}

void SMContextsCollectionApi::sm_contexts_collection_api_default_handler(const Pistache::Rest::Request &, Pistache::Http::ResponseWriter response) {
    response.send(Pistache::Http::Code::Not_Found, "The requested method does not exist");
}

}
}
}

