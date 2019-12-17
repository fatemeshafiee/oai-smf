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

#include "IndividualSMContextApiImpl.h"

namespace oai {
namespace smf_server {
namespace api {

using namespace oai::smf_server::model;

IndividualSMContextApiImpl::IndividualSMContextApiImpl(std::shared_ptr<Pistache::Rest::Router> rtr,  smf::smf_app *smf_app_inst, std::string address)
    : IndividualSMContextApi(rtr), m_smf_app(smf_app_inst), m_address(address)
    { }

void IndividualSMContextApiImpl::release_sm_context(const std::string &smContextRef, const SmContextReleaseData &smContextReleaseData, Pistache::Http::ResponseWriter &response) {
	Logger::smf_api_server().info("release_sm_context...");
	response.send(Pistache::Http::Code::Ok, "Release_sm_context API has not been implemented yet!\n");
}

void IndividualSMContextApiImpl::retrieve_sm_context(const std::string &smContextRef, const SmContextRetrieveData &smContextRetrieveData, Pistache::Http::ResponseWriter &response) {
	Logger::smf_api_server().info("retrieve_sm_context...");
	response.send(Pistache::Http::Code::Ok, "Retrieve_sm_context API has not been implemented yet!\n");
}

void IndividualSMContextApiImpl::update_sm_context(const std::string &smContextRef, const SmContextUpdateData &smContextUpdateData, Pistache::Http::ResponseWriter &response) {
	//handle Nsmf_PDUSession_UpdateSMContext Request
	Logger::smf_api_server().info("update_sm_contexts...");
	//Get the SmContextUpdateData from this message and process in smf_app
	smf::pdu_session_update_sm_context_request sm_context_req_msg = {};
	//smContextRef in our case is Supi
	supi_t supi =  {.length = 0};
	smf_string_to_supi(&supi, smContextRef.c_str());
	//supi64_t supi64 = smf_supi_to_u64(supi);
	sm_context_req_msg.set_supi(supi);

	//TODO: initialize necessary values for sm context req from smContextUpdateData and smContextRef

	std::shared_ptr<itti_n11_update_sm_context_request> itti_msg = std::make_shared<itti_n11_update_sm_context_request>(TASK_SMF_N11, TASK_SMF_APP, response);
	itti_msg->req = sm_context_req_msg;
	m_smf_app->handle_amf_msg(itti_msg);

}

}
}
}

