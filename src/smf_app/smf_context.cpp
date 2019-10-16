/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file smf_context.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "itti.hpp"
#include "logger.hpp"
#include "smf_app.hpp"
#include "smf_config.hpp"
#include "smf_context.hpp"
#include "smf_paa_dynamic.hpp"
#include "smf_procedure.hpp"
#include "ProblemDetails.h"
#include "3gpp_29.502.h"
#include "3gpp_24.501.h"
#include "SmContextCreatedData.h"
#include <algorithm>

using namespace smf;

extern itti_mw *itti_inst;
extern smf::smf_app *smf_app_inst;
extern smf::smf_config smf_cfg;

//------------------------------------------------------------------------------
void pgw_eps_bearer::release_access_bearer()
{
  released = true;
}
//------------------------------------------------------------------------------
std::string pgw_eps_bearer::toString() const
{
  std::string s = {};
  s.append("EPS BEARER:\n");
  s.append("\tEBI:\t\t\t\t").append(std::to_string(ebi.ebi)).append("\n");
  s.append("\tTFT:\t\t\t\tTODO tft").append("\n");
  s.append("\tSGW FTEID S5S8 UP:\t\t").append(sgw_fteid_s5_s8_up.toString()).append("\n");
  s.append("\tPGW FTEID S5S8 UP:\t\t").append(pgw_fteid_s5_s8_up.toString()).append("\n");
  s.append("\tBearer QOS:\t\t\t").append(eps_bearer_qos.toString()).append("\n");
  s.append("\tPDR ID UL:\t\t\t").append(std::to_string(pdr_id_ul.rule_id)).append("\n");
  s.append("\tPDR ID DL:\t\t\t").append(std::to_string(pdr_id_dl.rule_id)).append("\n");
  s.append("\tPRECEDENCE:\t\t\t").append(std::to_string(precedence.precedence)).append("\n");
  if (far_id_ul.first) {
    s.append("\tFAR ID UL:\t\t\t").append(std::to_string(far_id_ul.second.far_id)).append("\n");
  }
  if (far_id_dl.first) {
    s.append("\tFAR ID DL:\t\t\t").append(std::to_string(far_id_dl.second.far_id)).append("\n");
  }
  return s;
}
//------------------------------------------------------------------------------
void pgw_eps_bearer::deallocate_ressources()
{
  Logger::smf_app().info( "pgw_eps_bearer::deallocate_ressources(%d)", ebi.ebi);
  //if (not is_fteid_zero(pgw_fteid_s5_s8_up))
    //smf_app_inst->free_s5s8_up_fteid(pgw_fteid_s5_s8_up);
  clear();
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::set(const paa_t& paa)
{
  switch (paa.pdn_type.pdn_type) {
  case PDN_TYPE_E_IPV4:
    ipv4 = true;
    ipv6 = false;
    ipv4_address = paa.ipv4_address;
    break;
  case PDN_TYPE_E_IPV6:
    ipv4 = false;
    ipv6 = true;
    ipv6_address = paa.ipv6_address;
    break;
  case PDN_TYPE_E_IPV4V6:
    ipv4 = true;
    ipv6 = true;
    ipv4_address = paa.ipv4_address;
    ipv6_address = paa.ipv6_address;
    break;
  case PDN_TYPE_E_NON_IP:
    ipv4 = false;
    ipv6 = false;
    break;
  default:
    Logger::smf_app().error( "pgw_pdn_connection::set(paa_t) Unknown PDN type %d", paa.pdn_type.pdn_type);
  }
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::add_eps_bearer(pgw_eps_bearer& bearer)
{
  if ((bearer.ebi.ebi >= EPS_BEARER_IDENTITY_FIRST) and (bearer.ebi.ebi <= EPS_BEARER_IDENTITY_LAST)) {
    eps_bearers.erase(bearer.ebi.ebi);
    eps_bearers.insert(std::pair<uint8_t,pgw_eps_bearer>(bearer.ebi.ebi, bearer));
    Logger::smf_app().trace( "pgw_pdn_connection::add_eps_bearer(%d) success", bearer.ebi.ebi);
  } else {
    Logger::smf_app().error( "pgw_pdn_connection::add_eps_bearer(%d) failed, invalid EBI", bearer.ebi.ebi);
  }
}

//------------------------------------------------------------------------------
pgw_eps_bearer& pgw_pdn_connection::get_eps_bearer(const ebi_t& ebi)
{
  return eps_bearers[ebi.ebi];
}

//------------------------------------------------------------------------------
bool pgw_pdn_connection::find_eps_bearer(const pfcp::pdr_id_t& pdr_id, pgw_eps_bearer& bearer)
{
  for (std::map<uint8_t,pgw_eps_bearer>::iterator it=eps_bearers.begin(); it!=eps_bearers.end(); ++it) {
    if ((it->second.pdr_id_ul == pdr_id) || (it->second.pdr_id_dl == pdr_id)) {
      bearer = it->second;
      return true;
    }
  }
  return false;
}
//------------------------------------------------------------------------------
bool pgw_pdn_connection::has_eps_bearer(const pfcp::pdr_id_t& pdr_id, ebi_t& ebi)
{
  for (std::map<uint8_t,pgw_eps_bearer>::iterator it=eps_bearers.begin(); it!=eps_bearers.end(); ++it) {
    if ((it->second.pdr_id_ul == pdr_id) || (it->second.pdr_id_dl == pdr_id)) {
      ebi = it->second.ebi;
      return true;
    }
  }
  return false;
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::remove_eps_bearer(const ebi_t& ebi)
{
  pgw_eps_bearer& bearer = eps_bearers[ebi.ebi];
  bearer.deallocate_ressources();
  eps_bearers.erase(ebi.ebi);
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::remove_eps_bearer(pgw_eps_bearer& bearer)
{
  ebi_t ebi = {.ebi = bearer.ebi.ebi};
  bearer.deallocate_ressources();
  eps_bearers.erase(ebi.ebi);
}

//------------------------------------------------------------------------------
void pgw_pdn_connection::deallocate_ressources(const std::string& apn)
{
  for (std::map<uint8_t,pgw_eps_bearer>::iterator it=eps_bearers.begin(); it!=eps_bearers.end(); ++it) {
    it->second.deallocate_ressources();
  }
  eps_bearers.clear();
  if (ipv4) {
    paa_dynamic::get_instance().release_paa(apn, ipv4_address);
  }
  //smf_app_inst->free_s5s8_cp_fteid(pgw_fteid_s5_s8_cp);
  clear();
}
//------------------------------------------------------------------------------
void pgw_pdn_connection::generate_seid()
{
  // DO it simple now:
 // seid = pgw_fteid_s5_s8_cp.teid_gre_key | (((uint64_t)smf_cfg.instance) << 32);
}

void pgw_pdn_connection::set_seid(const uint64_t& s){
	seid = s;
}

//------------------------------------------------------------------------------
// TODO check if prd_id should be uniq in the (S)PGW-U or in the context of a pdn connection
void pgw_pdn_connection::generate_far_id(pfcp::far_id_t& far_id)
{
  far_id.far_id = far_id_generator.get_uid();
}
//------------------------------------------------------------------------------
// TODO check if prd_id should be uniq in the (S)PGW-U or in the context of a pdn connection
void pgw_pdn_connection::release_far_id(const pfcp::far_id_t& far_id)
{
  far_id_generator.free_uid(far_id.far_id);
}
//------------------------------------------------------------------------------
// TODO check if prd_id should be uniq in the (S)PGW-U or in the context of a pdn connection
void pgw_pdn_connection::generate_pdr_id(pfcp::pdr_id_t& pdr_id)
{
  pdr_id.rule_id = pdr_id_generator.get_uid();
}
//------------------------------------------------------------------------------
// TODO check if prd_id should be uniq in the (S)PGW-U or in the context of a pdn connection
void pgw_pdn_connection::release_pdr_id(const pfcp::pdr_id_t& pdr_id)
{
  pdr_id_generator.free_uid(pdr_id.rule_id);
}

//------------------------------------------------------------------------------
std::string pgw_pdn_connection::toString() const
{
  std::string s = {};
  s.append("PDN CONNECTION:\n");
  s.append("\tPDN type:\t\t\t").append(pdn_type.toString()).append("\n");
  if (ipv4)
    s.append("\tPAA IPv4:\t\t\t").append(conv::toString(ipv4_address)).append("\n");
  if (ipv6)
    s.append("\tPAA IPv6:\t\t\t").append(conv::toString(ipv6_address)).append("\n");
  s.append("\tDefault EBI:\t\t\t").append(std::to_string(default_bearer.ebi)).append("\n");
  s.append("\tSEID:\t\t\t").append(std::to_string(seid)).append("\n");
  for (auto it : eps_bearers) {
      s.append(it.second.toString());
  }
  return s;
}

//------------------------------------------------------------------------------
void smf_context::insert_procedure(std::shared_ptr<smf_procedure>& sproc)
{
  std::unique_lock<std::recursive_mutex> lock(m_context);
  pending_procedures.push_back(sproc);
}
//------------------------------------------------------------------------------
bool smf_context::find_procedure(const uint64_t& trxn_id, std::shared_ptr<smf_procedure>& proc)
{
  std::unique_lock<std::recursive_mutex> lock(m_context);
  auto found = std::find_if(pending_procedures.begin(), pending_procedures.end(),
                   [trxn_id](std::shared_ptr<smf_procedure> const& i) -> bool { return i->trxn_id == trxn_id;});
  if (found != pending_procedures.end()) {
    proc = *found;
    return true;
  }
  return false;
}
//------------------------------------------------------------------------------
void smf_context::remove_procedure(smf_procedure* proc)
{
  std::unique_lock<std::recursive_mutex> lock(m_context);
  auto found = std::find_if(pending_procedures.begin(), pending_procedures.end(), [proc](std::shared_ptr<smf_procedure> const& i) {
    return i.get() == proc;
  });
  if (found != pending_procedures.end()) {
    pending_procedures.erase(found);
  }
}


//------------------------------------------------------------------------------
void smf_context::handle_itti_msg (itti_n4_session_establishment_response& seresp)
{
  std::shared_ptr<smf_procedure> proc = {};
  if (find_procedure(seresp.trxn_id, proc)) {
    Logger::smf_app().debug("Received N4 SESSION ESTABLISHMENT RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64"\n", seresp.seid, seresp.trxn_id);
    proc->handle_itti_msg(seresp);
    remove_procedure(proc.get());
  } else {
    Logger::smf_app().debug("Received N4 SESSION ESTABLISHMENT RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64", smf_procedure not found, discarded!", seresp.seid, seresp.trxn_id);
  }
}
//------------------------------------------------------------------------------
void smf_context::handle_itti_msg (itti_n4_session_modification_response& smresp)
{
  std::shared_ptr<smf_procedure> proc = {};
  if (find_procedure(smresp.trxn_id, proc)) {
    Logger::smf_app().debug("Received N4 SESSION MODIFICATION RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64"\n", smresp.seid, smresp.trxn_id);
    proc->handle_itti_msg(smresp);
    remove_procedure(proc.get());
  } else {
    Logger::smf_app().debug("Received N4 SESSION MODIFICATION RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64", smf_procedure not found, discarded!", smresp.seid, smresp.trxn_id);
  }
  std::cout << toString() << std::endl;
}
//------------------------------------------------------------------------------
void smf_context::handle_itti_msg (itti_n4_session_deletion_response& sdresp)
{
  std::shared_ptr<smf_procedure> proc = {};
  if (find_procedure(sdresp.trxn_id, proc)) {
    Logger::smf_app().debug("Received N4 SESSION DELETION RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64"\n", sdresp.seid, sdresp.trxn_id);
    proc->handle_itti_msg(sdresp);
    remove_procedure(proc.get());
  } else {
    Logger::smf_app().debug("Received N4 SESSION DELETION RESPONSE sender teid " TEID_FMT "  pfcp_tx_id %" PRIX64", smf_procedure not found, discarded!", sdresp.seid, sdresp.trxn_id);
  }
  std::cout << toString() << std::endl;
}
//------------------------------------------------------------------------------
void smf_context::handle_itti_msg (std::shared_ptr<itti_n4_session_report_request>& req)
{/*
  pfcp::report_type_t report_type;
  if (req->pfcp_ies.get(report_type)) {
    pfcp::pdr_id_t pdr_id;
    // Downlink Data Report
    if (report_type.dldr) {
      pfcp::downlink_data_report data_report;
      if (req->pfcp_ies.get(data_report)) {
        pfcp::pdr_id_t pdr_id;
        if (data_report.get(pdr_id)) {
          std::shared_ptr<pgw_pdn_connection> ppc = {};
          ebi_t ebi;
          if (find_pdn_connection(pdr_id, ppc, ebi)) {
            downlink_data_report_procedure* p = new downlink_data_report_procedure(req);
            std::shared_ptr<smf_procedure> sproc = std::shared_ptr<smf_procedure>(p);
            insert_procedure(sproc);
            if (p->run(shared_from_this(), ppc, ebi)) {
              // TODO handle error code
              Logger::smf_app().info( "S5S8 DOWNLINK_DATA_REPORT procedure failed");
              remove_procedure(p);
            } else {
            }
          }
        }
      }
    }
    // Usage Report
    if (report_type.usar) {
      Logger::smf_app().debug("TODO PFCP_SESSION_REPORT_REQUEST/Usage Report");
    }
    // Error Indication Report
    if (report_type.erir) {
      Logger::smf_app().debug("TODO PFCP_SESSION_REPORT_REQUEST/Error Indication Report");
    }
    // User Plane Inactivity Report
    if (report_type.upir) {
      Logger::smf_app().debug("TODO PFCP_SESSION_REPORT_REQUEST/User Plane Inactivity Report");
    }
  }
  */
}

//------------------------------------------------------------------------------
std::string smf_context::toString() const
{
  std::unique_lock<std::recursive_mutex> lock(m_context);
  std::string s = {};
  s.append("PGW CONTEXT:\n");
  s.append("\tIMSI:\t\t\t\t").append(imsi.toString()).append("\n");
  s.append("\tIMSI UNAUTHENTICATED:\t\t").append(std::to_string(imsi_unauthenticated_indicator)).append("\n");
  for (auto it : dnns) {
    s.append(it->toString());
  }

	//s.append("\tIMSI:\t"+toString(p.msisdn));
	//apns.reserve(MAX_APN_PER_UE);
	return s;
}




//TTN
//------------------------------------------------------------------------------
void smf_context::handle_amf_msg (std::shared_ptr<itti_n11_create_sm_context_request> smreq)
{

	Logger::smf_app().info("Handle a PDU Session Create SM Context Request message from AMF");
	pdu_session_create_sm_context_request sm_context_req_msg = smreq->req;

	oai::smf_server::model::SmContextCreateError smContextCreateError;
	oai::smf_server::model::ProblemDetails problem_details;
	bool request_accepted = true;

	//Step 1. get necessary information
	std::string dnn = sm_context_req_msg.get_dnn();
	snssai_t snssai  =  sm_context_req_msg.get_snssai();
	request_type_t request_type = sm_context_req_msg.get_request_type();
	supi_t supi =  sm_context_req_msg.get_supi();
	supi64_t supi64 = smf_supi_to_u64(supi);
	uint32_t pdu_session_id = sm_context_req_msg.get_pdu_session_id();

	//Step 2. check the validity of the UE request, if valid send PDU Session Accept, otherwise send PDU Session Reject to AMF
	if (!verify_sm_context_request(smreq)){ //TODO: Need to implement this function
		// Not a valid request...
		Logger::smf_app().warn("Received PDU_SESSION_CREATESMCONTEXT_REQUEST, the request is not valid!");

		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_SUBSCRIPTION_DENIED]); //TODO: add causes to header file
		smContextCreateError.setError(problem_details);
		//TODO: to be completed when finishing NAS implementation
		//TODO: create a PDU Session Establishment Response by relying on NAS and assign to smContextCeateError.m_N1SmMsg
		send_create_session_response_error(smContextCreateError, Pistache::Http::Code::Forbidden, smreq->http_response);
		return;
	}

	//store HttpResponse and session-related information to be used when receiving the response from UPF
	itti_n11_create_sm_context_response *sm_context_resp = new itti_n11_create_sm_context_response(TASK_SMF_APP, TASK_SMF_N11, smreq->http_response);
	std::shared_ptr<itti_n11_create_sm_context_response> sm_context_resp_pending = std::shared_ptr<itti_n11_create_sm_context_response>(sm_context_resp);
	sm_context_resp->res.set_supi(supi);
	sm_context_resp->res.set_cause(REQUEST_ACCEPTED);

	//Step 3. find pdn_connection
	std::shared_ptr<dnn_context> sd;
	bool find_dnn = find_dnn_context (dnn, sd);

	//step 3.1. create dnn context if not exist
	//At this step, this context should be existed
	if (nullptr == sd.get()) {
		Logger::smf_app().debug("DNN context (dnn_in_use %s) is not existed yet!", dnn.c_str());
		dnn_context *d = new (dnn_context);

		d->in_use = true;
		d->dnn_in_use = dnn;
		//ambr
		sd = std::shared_ptr<dnn_context> (d);
		insert_dnn(sd);
	} else {
		sd.get()->dnn_in_use = dnn;
		Logger::smf_app().debug("DNN context (dnn_in_use %s) is already existed", dnn.c_str());
	}

	//step 3.2. create pdn connection if not exist
	std::shared_ptr<pgw_pdn_connection> sp;
	bool find_pdn = sd.get()->find_pdn_connection(pdu_session_id, sp);

	if (nullptr == sp.get()){
		Logger::smf_app().debug("Create a new PDN connection!");
		//create a new pdn connection
		pgw_pdn_connection *p = new (pgw_pdn_connection);
		p->pdn_type.pdn_type = sm_context_req_msg.get_pdu_session_type();
		p->pdu_session_id = pdu_session_id; //should check also nas_msg.pdusessionidentity ??
		//amf id
		p->amf_id = sm_context_req_msg.get_serving_nf_id();
		sp = std::shared_ptr<pgw_pdn_connection>(p);
		sd->insert_pdn_connection(sp);
	} else{
		Logger::smf_app().debug("PDN connection is already existed!");
		//TODO:
	}

	//pending session??
	//Step 4. check if supi is authenticated

	//address allocation based on PDN type
	//Step 5. paa
	bool set_paa = false;
	paa_t paa = {};

	//Step 6. pco
	//section 6.2.4.2, TS 24.501
	//If the UE wants to use DHCPv4 for IPv4 address assignment, it shall indicate that to the network within the Extended
	//protocol configuration options IE in the PDU SESSION ESTABLISHMENT REQUEST
	//Extended protocol configuration options: See subclause 10.5.6.3A in 3GPP TS 24.008.

	//ExtendedProtocolConfigurationOptions extended_protocol_options = (sm_context_req_msg.get_nas_msg()).extendedprotocolconfigurationoptions;
	//TODO: PCO
	protocol_configuration_options_t pco_resp = {};
	protocol_configuration_options_ids_t pco_ids = {
			.pi_ipcp = 0,
			.ci_dns_server_ipv4_address_request = 0,
			.ci_ip_address_allocation_via_nas_signalling = 0,
			.ci_ipv4_address_allocation_via_dhcpv4 = 0,
			.ci_ipv4_link_mtu_request = 0};

	//smf_app_inst->process_pco_request(extended_protocol_options, pco_resp, pco_ids);

	//Step 7. address allocation based on PDN type
	switch (sp->pdn_type.pdn_type) {
	case PDN_TYPE_E_IPV4: {
		if (!pco_ids.ci_ipv4_address_allocation_via_dhcpv4) { //use NAS signalling
			//use NAS signalling
			//static or dynamic address allocation
			bool paa_res = false; //how to define static or dynamic
			//depend of subscription information: staticIpAddress in DNN Configuration
			//TODO: check static IP address is available in the subscription information (SessionManagementSubscription) or in DHCP/DN-AAA

			std::shared_ptr<session_management_subscription> ss;
			std::shared_ptr<dnn_configuration_t> sdc;
			find_dnn_subscription(snssai, ss);
			if (nullptr != ss.get()){
				ss.get()->find_dnn_configuration(sd->dnn_in_use, sdc);
				if (nullptr != sdc.get()){
					paa.pdn_type.pdn_type = sdc.get()->pdu_session_types.default_session_type.pdu_session_type;
					//TODO: static ip addr
				}
			}

			if ((not paa_res) || (not paa.is_ip_assigned())) {
				bool success = paa_dynamic::get_instance().get_free_paa(sd->dnn_in_use, paa);
				if (success) {
					set_paa = true;
				} else {
					//cause: ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED; //check for 5G?
				}
				// Static IP address allocation
			} else if ((paa_res) && (paa.is_ip_assigned())) {
				set_paa = true;
			}
			Logger::smf_app().info( "PAA, Ipv4 Address: %s", inet_ntoa (*((struct in_addr *)&paa.ipv4_address)));
		} else { //use DHCP
			//TODO: DHCP
		}

	}
	break;

	case PDN_TYPE_E_IPV6: {
		//TODO:
	}
	break;

	case PDN_TYPE_E_IPV4V6: {
		//TODO:
	}
	break;

	default:
		Logger::smf_app().error( "Unknown PDN type %d", sp->pdn_type.pdn_type);
		problem_details.setCause(pdu_session_application_error_e2str[PDU_SESSION_APPLICATION_ERROR_PDUTYPE_NOT_SUPPORTED]);
		smContextCreateError.setError(problem_details);
		//TODO: to be completed when finishing NAS implementation
		//TODO: create a PDU Session Establishment Response by relying on NAS and assign to smContextCeateError.m_N1SmMsg
		send_create_session_response_error(smContextCreateError, Pistache::Http::Code::Forbidden, sm_context_resp->http_response);
		request_accepted = false;
		break;
	}

	//TODO: if "Integrity Protection is required", check UE Integrity Protection Maximum Data Rate
	//TODO: (Optional) Secondary authentication/authorization

	//Step 8. create session establishment procedure and run the procedure
	//if request is accepted
	if (request_accepted){
		if (set_paa) {
			sm_context_resp_pending->res.set_paa(paa); //will be used when procedure is running
			sp->set(paa);
		} else {
			// Valid PAA sent in CSR ?
			//bool paa_res = csreq->gtp_ies.get(paa);
			//if ((paa_res) && ( paa.is_ip_assigned())) {
			//	sp->set(paa);
			//}
		}

		//Send reply to AMF (PDUSession_CreateSMContextResponse including Cause, SMContextId)
		//location header contains the URI of the created resource
		Logger::smf_app().info("Sending response to AMF!");
		nlohmann::json jsonData;
		oai::smf_server::model::SmContextCreatedData smContextCreatedData;
		//include only SmfServiceInstanceId (See section 6.1.6.2.3, 3GPP TS 29.502 v16.0.0)

		to_json(jsonData, smContextCreatedData);
		std::string resBody = jsonData.dump();
		sm_context_resp->http_response.send(Pistache::Http::Code::Created, resBody);

		session_create_sm_context_procedure* proc = new session_create_sm_context_procedure(sp);
		std::shared_ptr<smf_procedure> sproc = std::shared_ptr<smf_procedure>(proc);

		insert_procedure(sproc);
		if (proc->run(smreq, sm_context_resp_pending, shared_from_this())) {
			// error !
			Logger::smf_app().info( "PDU SESSION CREATE SM CONTEXT REQUEST procedure failed");
			remove_procedure(proc);
		}

	}else{ //if request is rejected
		//TODO:
		//un-subscribe to the modifications of Session Management Subscription data for (SUPI, DNN, S-NSSAI)
	}

	//step 9. if error when establishing the pdu session, send ITTI message to APP to trigger N1N2MessageTransfer towards AMFs
	if (sm_context_resp->res.get_cause() != REQUEST_ACCEPTED) {
		//clear pco, ambr
        //TODO:
		//free paa
		paa_t free_paa = {};
		free_paa = sm_context_resp->res.get_paa();
		if (free_paa.is_ip_assigned()){
			switch (sp->pdn_type.pdn_type) {
			case PDN_TYPE_E_IPV4:
			case PDN_TYPE_E_IPV4V6:
				paa_dynamic::get_instance().release_paa (sd->dnn_in_use, free_paa.ipv4_address);
				break;

			case PDN_TYPE_E_IPV6:
			case PDN_TYPE_E_NON_IP:
			default:;
			}
			//sm_context_resp->res.clear_paa(); //TODO:
		}
		//clear the created context??
		//TODO:

/*
		for (auto it : sm_context_resp->res.bearer_contexts_to_be_created) {
			gtpv2c::bearer_context_created_within_create_session_response bcc = {};
			cause_t bcc_cause = {.cause_value = NO_RESOURCES_AVAILABLE, .pce = 0, .bce = 0, .cs = 0};
			bcc.set(it.eps_bearer_id);
			bcc.set(bcc_cause);
			//sm_context_resp->res.add_bearer_context_created(bcc);
		}
*/
		//send ITTI message to N11 interface to trigger N1N2MessageTransfer towards AMFs
		//with N1SM container with a PDU Session Establishment Reject message
		//TODO
		//sm_context_resp_pending->res.set
		Logger::smf_app().info( "Sending ITTI message %s to task TASK_SMF_N11", sm_context_resp_pending->get_msg_name());

		int ret = itti_inst->send_msg(sm_context_resp_pending);
		if (RETURNok != ret) {
			Logger::smf_app().error( "Could not send ITTI message %s to task TASK_SMF_N11",  sm_context_resp_pending->get_msg_name());
		}

	}


}

//------------------------------------------------------------------------------
bool smf_context::find_dnn_context(const std::string& dnn, std::shared_ptr<dnn_context>& dnn_context)
{
	std::unique_lock<std::recursive_mutex> lock(m_context);
	for (auto it : dnns) {
		if (0 == dnn.compare(it->dnn_in_use)) {
			dnn_context = it;
			return true;
		}
	}
	return false;
}

//------------------------------------------------------------------------------
void smf_context::insert_dnn(std::shared_ptr<dnn_context>& sd)
{
	std::unique_lock<std::recursive_mutex> lock(m_context);
	dnns.push_back(sd);
}

//------------------------------------------------------------------------------
bool smf_context::verify_sm_context_request(std::shared_ptr<itti_n11_create_sm_context_request> smreq)
{
	//check the validity of the UE request according to the user subscription or local policies
	//TODO:
	return true;
}

//------------------------------------------------------------------------------
void smf_context::send_create_session_response_error(oai::smf_server::model::SmContextCreateError& smContextCreateError, Pistache::Http::Code code, Pistache::Http::ResponseWriter& httpResponse)
{
	//Send reply to AMF
	nlohmann::json jsonData;
	to_json(jsonData, smContextCreateError);
	std::string resBody = jsonData.dump();
	httpResponse.send(code, resBody);
}

//------------------------------------------------------------------------------
bool dnn_context::find_pdn_connection(const uint32_t pdu_session_id , std::shared_ptr<pgw_pdn_connection>& pdn)
{
	pdn = {};

	std::unique_lock<std::recursive_mutex> lock(m_context);
	for (auto it : pdn_connections) {
		if (pdu_session_id == it->pdu_session_id) {
			pdn = it;
			return true;
		}
	}
	return false;
}

//------------------------------------------------------------------------------
void dnn_context::insert_pdn_connection(std::shared_ptr<pgw_pdn_connection>& sp)
{
	std::unique_lock<std::recursive_mutex> lock(m_context);
	pdn_connections.push_back(sp);
}

//------------------------------------------------------------------------------
std::string dnn_context::toString() const
{
  std::string s = {};
  s.append("DNN CONTEXT:\n");
  s.append("\tIn use:\t\t\t\t").append(std::to_string(in_use)).append("\n");
  s.append("\tDNN:\t\t\t\t").append(dnn_in_use).append("\n");
  //s.append("\tAPN AMBR Bitrate Uplink:\t").append(std::to_string(apn_ambr.br_ul)).append("\n");
  //s.append("\tAPN AMBR Bitrate Downlink:\t").append(std::to_string(apn_ambr.br_dl)).append("\n");
  for (auto it : pdn_connections) {
    s.append(it->toString());
  }
  return s;
}

//------------------------------------------------------------------------------
void session_management_subscription::insert_dnn_configuration(std::string dnn, std::shared_ptr<dnn_configuration_t>& dnn_configuration){
	dnn_configurations.insert(std::pair<std::string, std::shared_ptr<dnn_configuration_t>>(dnn,dnn_configuration));
}

//------------------------------------------------------------------------------
void session_management_subscription::find_dnn_configuration(std::string dnn, std::shared_ptr<dnn_configuration_t>& dnn_configuration){
	if (dnn_configurations.count(dnn) > 0){
	   dnn_configuration = dnn_configurations.at(dnn);
	}
}

//------------------------------------------------------------------------------
void smf_context::insert_dnn_subscription(snssai_t snssai, std::shared_ptr<session_management_subscription>& ss)
{
	std::unique_lock<std::recursive_mutex> lock(m_context);
	dnn_subscriptions.insert (std::pair ((uint8_t)snssai.sST, ss));

}

//------------------------------------------------------------------------------
bool smf_context::find_dnn_subscription(const snssai_t snssai, std::shared_ptr<session_management_subscription>& ss)
{
	std::unique_lock<std::recursive_mutex> lock(m_context);
	if (dnn_subscriptions.count(snssai.sST) > 0 ){
		ss = dnn_subscriptions.at(snssai.sST);
		return true;
	}
	return false;
}
