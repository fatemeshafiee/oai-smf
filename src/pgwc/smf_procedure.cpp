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

#include "3gpp_29.244.h"
#include "3gpp_29.274.h"
#include "common_defs.h"
#include "3gpp_conversions.hpp"
#include "conversions.hpp"
#include "itti.hpp"
#include "itti_msg_n4_restore.hpp"
#include "logger.hpp"
#include "msg_gtpv2c.hpp"
#include "pgw_app.hpp"
#include "smf_config.hpp"
#include "smf_pfcp_association.hpp"
#include "smf_procedure.hpp"
#include "pgw_context.hpp"
#include "SmContextCreatedData.h"

#include <algorithm>    // std::search

using namespace pfcp;
using namespace pgwc;
using namespace std;

extern itti_mw *itti_inst;
extern pgwc::pgw_app *pgw_app_inst;
extern pgwc::smf_config smf_cfg;

//------------------------------------------------------------------------------
int sx_session_restore_procedure::run()
{
	if (pending_sessions.size()) {
		itti_n4_restore *itti_msg = nullptr;
		for (std::set<pfcp::fseid_t>::iterator it=pending_sessions.begin(); it!=pending_sessions.end();++it) {
			if (!itti_msg) {
				itti_msg = new itti_n4_restore(TASK_SMF_N4, TASK_PGWC_APP);
			}
			itti_msg->sessions.insert(*it);
			if (itti_msg->sessions.size() >= 64) {
				std::shared_ptr<itti_n4_restore> i = std::shared_ptr<itti_n4_restore>(itti_msg);
				int ret = itti_inst->send_msg(i);
				if (RETURNok != ret) {
					Logger::pgwc_sx().error( "Could not send ITTI message %s to task TASK_PGWC_APP", i->get_msg_name());
				}
				itti_msg = nullptr;
			}
		}
		if (itti_msg) {
			std::shared_ptr<itti_n4_restore> i = std::shared_ptr<itti_n4_restore>(itti_msg);
			int ret = itti_inst->send_msg(i);
			if (RETURNok != ret) {
				Logger::pgwc_sx().error( "Could not send ITTI message %s to task TASK_PGWC_APP", i->get_msg_name());
				return RETURNerror;
			}
		}
	}
	return RETURNok;
}


//------------------------------------------------------------------------------
int session_create_sm_context_procedure::run(std::shared_ptr<itti_n11_create_sm_context_request> sm_context_req, std::shared_ptr<itti_n11_create_sm_context_response> sm_context_resp, std::shared_ptr<pgwc::pgw_context> pc)
{

	// TODO check if compatible with ongoing procedures if any
	pfcp::node_id_t up_node_id = {};
	if (not pfcp_associations::get_instance().select_up_node(up_node_id, NODE_SELECTION_CRITERIA_MIN_PFCP_SESSIONS)) {
		// TODO
		sm_context_resp->res.set_cause(REMOTE_PEER_NOT_RESPONDING); //verify for 5G??
		return RETURNerror;
	}


	//-------------------
	n11_trigger = sm_context_req;
	n11_triggered_pending = sm_context_resp;
	//ppc->generate_seid();
	uint64_t seid = pgw_app_inst->generate_seid();
	ppc->set_seid(seid);
	itti_n4_session_establishment_request *sx_ser = new itti_n4_session_establishment_request(TASK_PGWC_APP, TASK_SMF_N4);
	sx_ser->seid = 0;
	sx_ser->trxn_id = this->trxn_id;
	sx_ser->r_endpoint = endpoint(up_node_id.u1.ipv4_address, pfcp::default_port);
	sx_triggered = std::shared_ptr<itti_n4_session_establishment_request>(sx_ser);

	//-------------------
	// IE node_id_t
	//-------------------
	pfcp::node_id_t node_id = {};
	smf_cfg.get_pfcp_node_id(node_id);
	sx_ser->pfcp_ies.set(node_id);

	//-------------------
	// IE fseid_t
	//-------------------
	pfcp::fseid_t cp_fseid = {};
	smf_cfg.get_pfcp_fseid(cp_fseid);
	cp_fseid.seid = ppc->seid;
	sx_ser->pfcp_ies.set(cp_fseid);


	//*******************
	// UPLINK
	//*******************
	//-------------------
	// IE create_far (Forwarding Action Rules)
	//-------------------
	pfcp::create_far                  create_far = {};
	pfcp::far_id_t                    far_id = {}; //rule ID
	pfcp::apply_action_t              apply_action = {};
	pfcp::forwarding_parameters       forwarding_parameters = {};

	// forwarding_parameters IEs
	pfcp::destination_interface_t     destination_interface = {};

	ppc->generate_far_id(far_id);
	apply_action.forw = 1;

	destination_interface.interface_value = pfcp::INTERFACE_VALUE_CORE; // ACCESS is for downlink, CORE for uplink
	forwarding_parameters.set(destination_interface);

	create_far.set(far_id);
	create_far.set(apply_action);
	create_far.set(forwarding_parameters); //should check since destination interface is directly set to FAR (as described in Table 5.8.2.11.6-1)

	//-------------------
	// IE create_pdr (section 5.8.2.11.3@TS 23.501)
	//-------------------
	pfcp::create_pdr                  create_pdr = {};
	pfcp::pdr_id_t                    pdr_id = {};  //rule ID?
	pfcp::precedence_t                precedence = {};
	pfcp::pdi                         pdi = {}; //packet detection information
	pfcp::outer_header_removal_t      outer_header_removal = {};
	// pdi IEs
	pfcp::source_interface_t         source_interface = {};
	pfcp::fteid_t                    local_fteid = {};
	pfcp::ue_ip_address_t            ue_ip_address = {};
	pfcp::sdf_filter_t               sdf_filter = {};
	pfcp::application_id_t           application_id = {};
	pfcp::qfi_t                      qfi = {};

	source_interface.interface_value = pfcp::INTERFACE_VALUE_ACCESS;
	local_fteid.ch   = 1;
	//local_fteid.chid = 1;

	xgpp_conv::paa_to_pfcp_ue_ip_address(sm_context_resp->res.get_paa(), ue_ip_address);

	// DOIT simple
	// shall uniquely identify the PDR among all the PDRs configured for that PFCP session.
	ppc->generate_pdr_id(pdr_id);
	//precedence.precedence = it.bearer_level_qos.pl; //TODO

	//packet detection information
	pdi.set(source_interface); //source interface
	pdi.set(local_fteid); // CN tunnel info
	pdi.set(ue_ip_address); //UE IP address
	//TODO:
	//network instance (no need in this version)
	//QoS Flow ID

	outer_header_removal.outer_header_removal_description = OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4;

	create_pdr.set(pdr_id);
	create_pdr.set(precedence);
	create_pdr.set(pdi);
	create_pdr.set(outer_header_removal);
	create_pdr.set(far_id);
	//TODO: list of Usage reporting Rule IDs
	//TODO: list of QoS Enforcement Rule IDs

	//-------------------
	// ADD IEs to message
	//-------------------
	sx_ser->pfcp_ies.set(create_pdr);
	sx_ser->pfcp_ies.set(create_far);

	// Have to backup far id and pdr id
	pgw_eps_bearer b = {};
	b.far_id_ul.first = true;
	b.far_id_ul.second = far_id;
	b.pdr_id_ul = pdr_id;
	//b.ebi = it.eps_bearer_id;
	b.ebi = sm_context_req->req.get_pdu_session_id();
	pgw_eps_bearer b2 = b;
	ppc->add_eps_bearer(b2);


	// for finding procedure when receiving response
	pgw_app_inst->set_seid_2_pgw_context(cp_fseid.seid, pc);


	Logger::pgwc_app().info( "Sending ITTI message %s to task TASK_SMF_N4", sx_ser->get_msg_name());
	int ret = itti_inst->send_msg(sx_triggered);
	if (RETURNok != ret) {
		Logger::pgwc_app().error( "Could not send ITTI message %s to task TASK_SMF_N4", sx_ser->get_msg_name());
		return RETURNerror;
	}

	return RETURNok;
}

//------------------------------------------------------------------------------
void session_create_sm_context_procedure::handle_itti_msg (itti_n4_session_establishment_response& resp)
{
	Logger::pgwc_app().info( "session_create_sm_context_procedure handle itti_n4_session_establishment_response: pdu-session-id %d", n11_trigger.get()->req.get_pdu_session_id());

	pfcp::cause_t cause = {};
	resp.pfcp_ies.get(cause);
	if (cause.cause_value == pfcp::CAUSE_VALUE_REQUEST_ACCEPTED) {
		resp.pfcp_ies.get(ppc->up_fseid);
	}

	for (auto it : resp.pfcp_ies.created_pdrs) {
		pfcp::pdr_id_t pdr_id = {};
		pfcp::far_id_t far_id = {};
		if (it.get(pdr_id)) {
			pgw_eps_bearer b = {};
			if (ppc->get_eps_bearer(pdr_id, b)) {
				pfcp::fteid_t local_up_fteid = {};
				if (it.get(local_up_fteid)) {
					xgpp_conv::pfcp_to_core_fteid(local_up_fteid, b.pgw_fteid_s5_s8_up);
					b.pgw_fteid_s5_s8_up.interface_type = S5_S8_PGW_GTP_U;
                    //set tunnel id
					xgpp_conv::pfcp_to_core_fteid(local_up_fteid, b.ul_fteid);
					b.ul_fteid.interface_type = S1_U_SGW_GTP_U;
					// comment if SPGW-C allocate up fteid
					pgw_eps_bearer b2 = b;
					ppc->add_eps_bearer(b2);
				}
				// uncomment if SPGW-C allocate up fteid
				// ppc->add_eps_bearer(b);
			} else {
				Logger::pgwc_app().error( "Could not get EPS bearer for created_pdr %d", pdr_id.rule_id);
			}
		} else {
			Logger::pgwc_app().error( "Could not get pdr_id for created_pdr in %s", resp.pfcp_ies.get_msg_name());
		}
	}

	ebi_t ebi = {};
	ebi.ebi = n11_trigger.get()->req.get_pdu_session_id();
	pgw_eps_bearer b = {};
	gtpv2c::bearer_context_created_within_create_session_response bcc = {};
	::cause_t bcc_cause = {.cause_value = REQUEST_ACCEPTED, .pce = 0, .bce = 0, .cs = 0};
	if (not ppc->get_eps_bearer(ebi, b)) {
		bcc_cause.cause_value = SYSTEM_FAILURE;
	} else {
		if (b.ul_fteid.is_zero()) {
			bcc_cause.cause_value = SYSTEM_FAILURE;
		} else {
			bcc.set_s1_u_sgw_fteid(b.ul_fteid);
		}
	}
	bcc.set(b.ebi);
	bcc.set(bcc_cause);
	//TODO: for qos bearer bearer_qos_t bearer_qos = {}; if(b.get(bearer_qos)){bcc.set(bearer_level_qos)};

    //TODO
	//should send information of created bearer to AMF
	//n11_triggered_pending->add_bearer_context_created(bcc);
	//N1N2MessageTransferReqData
	//Step 11, section 4.3.2.2.1@TS 23.502
	//Namf_Communication_N1N2MessageTransfer (PDU Session ID,
	// N2 SM information (PDU Session ID, QFI(s), QoS Profile(s), CN Tunnel Info, S-NSSAI from the Allowed NSSAI, Session-AMBR, PDU
	//Session Type, User Plane Security Enforcement information, UE Integrity Protection Maximum Data Rate),
	//N1 SM container (PDU Session Establishment Accept (QoS Rule(s) and QoS Flow level QoS parameters if needed
	//for the QoS Flow(s) associated with the QoS rule(s), selected SSC mode, S-NSSAI(s), DNN, allocated IPv4
	//address, interface identifier, Session-AMBR, selected PDU Session Type, Reflective QoS Timer (if available),
	//P-CSCF address(es), [Always-on PDU Session])))

    //send ITTI message to N11 interface to trigger N1N2MessageTransfer towards AMFs
	Logger::pgwc_app().info( "Sending ITTI message %s to task TASK_SMF_N11", n11_triggered_pending->get_msg_name());

	int ret = itti_inst->send_msg(n11_triggered_pending);
	if (RETURNok != ret) {
		Logger::pgwc_app().error( "Could not send ITTI message %s to task TASK_SMF_N11",  n11_triggered_pending->get_msg_name());
	}

}

