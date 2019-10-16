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

#include "SMContextsCollectionApiImpl.h"
#include "logger.hpp"
#include "smf_msg.hpp"
#include "itti_msg_n11.hpp"

extern "C" {
#include <ctype.h>
#include "nas_message.h"
#include "mmData.h"
#include "nas_sm_encode_to_json.h"
}

namespace oai {
namespace smf {
namespace api {

using namespace oai::smf::model;

SMContextsCollectionApiImpl::SMContextsCollectionApiImpl(std::shared_ptr<Pistache::Rest::Router> rtr, pgwc::pgw_app *smf_app_inst)
: SMContextsCollectionApi(rtr), m_smf_app(smf_app_inst)

{ }

void SMContextsCollectionApiImpl::post_sm_contexts(const SmContextMessage &smContextMessage, Pistache::Http::ResponseWriter &response) {

	Logger::smf_api_server().info("post_sm_contexts...");

	//decode NAS message and assign the necessary informations to pgwc::pdu_session_create_sm_context_request
	//and pass this message to SMF to handle this message

	nas_message_t	decoded_nas_msg;
	memset (&decoded_nas_msg, 0, sizeof (nas_message_t));

	SmContextCreateData smContextCreateData = smContextMessage.getJsonData();
	std::string n1_sm_msg = smContextMessage.getBinaryDataN1SmMessage();
	
    //FOR DEBUG ONLY!!, GENERATE A PDU SESSION ESTABLISHMENT MESSAGE HERE!!
	//sm_encode_establishment_request();
	//m_smf_app->create_n1_sm_container(PDU_SESSION_ESTABLISHMENT_REQUEST, n1_sm_msg);

	Logger::smf_api_server().debug("smContextMessage, n1 sm msg %s",n1_sm_msg.c_str());

	//Step1. Decode N1 SM container into decoded nas msg
	int decoder_rc = m_smf_app->decode_nas_message_n1_sm_container(decoded_nas_msg, n1_sm_msg);

	Logger::smf_api_server().debug("nas header  decode extended_protocol_discriminator %d, security_header_type:%d,sequence_number:%d,message_authentication_code:%d\n",
			decoded_nas_msg.header.extended_protocol_discriminator,
			decoded_nas_msg.header.security_header_type,
			decoded_nas_msg.header.sequence_number,
			decoded_nas_msg.header.message_authentication_code);

	//Step 2. Create a pdu_session_create_sm_context_request message and store the necessary information
	pgwc::pdu_session_create_sm_context_request sm_context_req_msg = {};

	//supi
	supi_t supi =  {.length = 0};
	smf_string_to_supi(&supi, smContextCreateData.getSupi().c_str());
	sm_context_req_msg.set_supi(supi);
	Logger::smf_api_server().info("Supi %s", smContextCreateData.getSupi().c_str());

	//dnn
	sm_context_req_msg.set_dnn(smContextCreateData.getDnn());
	//S-Nssai
	snssai_t snssai(smContextCreateData.getSNssai().getSst(), smContextCreateData.getSNssai().getSd());
	sm_context_req_msg.set_snssai(snssai);
	//PDU session ID
	sm_context_req_msg.set_pdu_session_id(smContextCreateData.getPduSessionId());
	//AMF ID
	sm_context_req_msg.set_serving_nf_id(smContextCreateData.getServingNfId()); //TODO: should be verified that AMF ID is stored in GUAMI or ServingNfId
	//Request Type
	sm_context_req_msg.set_request_type(smContextCreateData.getRequestType());
	//PCF ID
	// Priority Access
	//User Location Information
	//Access Type
	// PEI
	// GPSI
	// UE presence in LADN service area
	// DNN Selection Mode
	sm_context_req_msg.set_dnn_selection_mode(smContextCreateData.getSelMode());
	//Subscription for PDU Session Status Notification
	// Trace requirement

	//From N1 Container (NAS)
	//Extended protocol discriminator (Mandatory)
	sm_context_req_msg.set_epd(decoded_nas_msg.header.extended_protocol_discriminator);
	//PDU session ID (Mandatory)
	sm_context_req_msg.set_pdu_session_id(decoded_nas_msg.plain.sm.header.pdu_session_identity);
	//PTI (Mandatory)
	procedure_transaction_id_t pti = {.procedure_transaction_id = decoded_nas_msg.plain.sm.header.procedure_transaction_identity};
	sm_context_req_msg.set_pti(pti);

	//Message type (Mandatory) (PDU SESSION ESTABLISHMENT REQUEST message identity)
	sm_context_req_msg.set_message_type(decoded_nas_msg.plain.sm.header.message_type);
	sm_context_req_msg.set_message_type (PDU_SESSION_ESTABLISHMENT_REQUEST); //Temporary - should be removed (get from NAS)

	//Integrity protection maximum data rate (Mandatory)

	//PDU session type (Optional)
	sm_context_req_msg.set_pdu_session_type(PDN_TYPE_E_IPV4);
	if (decoded_nas_msg.plain.sm.header.message_type == PDU_SESSION_ESTABLISHMENT_REQUEST){
		sm_context_req_msg.set_pdu_session_type(decoded_nas_msg.plain.sm.specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
	}

	//SSC mode (Optional)
	//5GSM capability (Optional)
	//Maximum number of supported (Optional)
	//Maximum number of supported packet filters (Optional)
	//Always-on PDU session requested (Optional)
	//SM PDU DN request container (Optional)
	//Extended protocol configuration options (Optional) e.g, FOR DHCP

	//Step 3. Handle the pdu_session_create_sm_context_request message in pwg_app
	//m_smf_app->handle_amf_msg(sm_context_req_msg, response);

    itti_n11_create_sm_context_request *itti_msg = new itti_n11_create_sm_context_request(TASK_SMF_N11, TASK_PGWC_APP, response);
    itti_msg->req = sm_context_req_msg;
    std::shared_ptr<itti_n11_create_sm_context_request> i = std::shared_ptr<itti_n11_create_sm_context_request>(itti_msg);

    m_smf_app->handle_amf_msg(i);

}

}
}
}
