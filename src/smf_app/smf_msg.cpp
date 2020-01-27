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

/*! \file smf_msg.cpp
  \brief
  \author  Tien-Thinh NGUYEN
  \company Eurecom
  \date 2019
  \email: tien-thinh.nguyen@eurecom.fr
 */
#include "smf_msg.hpp"


using namespace smf;

//-----------------------------------------------------------------------------
void qos_flow_context_created::set_cause(const uint8_t cause)
{
	cause_value = cause;
}
//-----------------------------------------------------------------------------
void qos_flow_context_created::set_qfi(const pfcp::qfi_t& q)
{
	qfi = q;
}
//-----------------------------------------------------------------------------
void qos_flow_context_created::set_ul_fteid(const fteid_t& teid)
{
	ul_fteid = teid;
}

//-----------------------------------------------------------------------------
pdu_session_msg_type_t pdu_session_msg::get_msg_type() const
{
	return m_msg_type;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_msg_type(pdu_session_msg_type_t const& msg_type)
{
	m_msg_type = msg_type;
}

//-----------------------------------------------------------------------------
supi_t pdu_session_msg::get_supi() const
{
	return m_supi;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_supi(supi_t const& supi)
{
	m_supi = supi;
}

//-----------------------------------------------------------------------------
std::string pdu_session_msg::get_supi_prefix() const
{
	return m_supi_prefix;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_supi_prefix(std::string const& prefix)
{
	m_supi_prefix = prefix;
}

//-----------------------------------------------------------------------------
pdu_session_id_t pdu_session_msg::get_pdu_session_id() const
{
	return m_pdu_session_id;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_pdu_session_id(pdu_session_id_t const pdu_session_id)
{
	m_pdu_session_id = pdu_session_id;
}

//-----------------------------------------------------------------------------
std::string pdu_session_msg::get_dnn() const
{
	return m_dnn;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_dnn(std::string const& dnn)
{
	m_dnn = dnn;
}

//-----------------------------------------------------------------------------
snssai_t pdu_session_msg::get_snssai() const
{
	return m_snssai;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_snssai(snssai_t const& snssai)
{
	m_snssai = snssai;
}

//-----------------------------------------------------------------------------
void pdu_session_msg::set_api_root(std::string const& value)
{
    m_api_root = value;
}

std::string pdu_session_msg::get_api_root() const
{
	return m_api_root;
}

//-----------------------------------------------------------------------------
uint8_t pdu_session_create_sm_context::get_pdu_session_type() const
{
	return m_pdu_session_type;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context::set_pdu_session_type (uint8_t const& pdu_session_type)
{
	m_pdu_session_type = pdu_session_type;
}

//-----------------------------------------------------------------------------
extended_protocol_discriminator_t pdu_session_create_sm_context::get_epd() const
{
	return m_epd;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context::set_epd(extended_protocol_discriminator_t const& epd)
{
	m_epd = epd;
}

//-----------------------------------------------------------------------------
procedure_transaction_id_t pdu_session_create_sm_context::get_pti() const
{
	return m_pti;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context::set_pti(procedure_transaction_id_t const& pti)
{
	m_pti = pti;
}

//-----------------------------------------------------------------------------
uint8_t pdu_session_create_sm_context::get_message_type() const
{
	return m_message_type;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context::set_message_type(uint8_t const& message_type){
	m_message_type = message_type;
}



std::string pdu_session_create_sm_context_request::get_n1_sm_message() const{
	return 	m_n1_sm_message;
}

void pdu_session_create_sm_context_request::set_n1_sm_message(std::string const& value){
	m_n1_sm_message = value;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_request::get_serving_nf_id() const
{
	return m_serving_nf_id;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_request::set_serving_nf_id(std::string const& serving_nf_id)
{
	m_serving_nf_id = serving_nf_id;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_request::get_request_type() const
{
	return m_request_type;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_request::set_request_type(std::string const& request_type)
{
	m_request_type = request_type;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_request::set_dnn_selection_mode(std::string const& dnn_selection_mode)
{
	m_dnn_selection_mode = dnn_selection_mode;
}

//-----------------------------------------------------------------------------
std::string pdu_session_create_sm_context_request::get_dnn_selection_mode() const
{
	return m_dnn_selection_mode;
}

//-----------------------------------------------------------------------------
ipmdr_t pdu_session_create_sm_context_request::get_ipmdr() const
{
	return m_ipmdr;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_request::set_ipmdr(ipmdr_t const& ipmdr)
{
	m_ipmdr = ipmdr;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_cause(uint8_t cause)
{
	m_cause = cause;
}

//-----------------------------------------------------------------------------
uint8_t pdu_session_create_sm_context_response::get_cause(){
	return m_cause;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_paa(paa_t paa)
{
	m_paa = paa;
}

//-----------------------------------------------------------------------------
paa_t pdu_session_create_sm_context_response::get_paa()
{
	return m_paa;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_http_code(Pistache::Http::Code code)
{
	m_code = code;
}

//-----------------------------------------------------------------------------
Pistache::Http::Code pdu_session_create_sm_context_response::get_http_code()
{
	return m_code;
}

//-----------------------------------------------------------------------------
void pdu_session_create_sm_context_response::set_qos_flow_context(const qos_flow_context_created qos_flow)
{
	qos_flow_context = qos_flow;
}

//-----------------------------------------------------------------------------
/* pdu_session_update_sm_context_request */
std::string pdu_session_update_sm_context_request::get_n2_sm_information() const{
	return 	n2_sm_information;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::set_n2_sm_information(std::string const& value){
	n2_sm_information = value;
}

//-----------------------------------------------------------------------------
std::string pdu_session_update_sm_context_request::get_n2_sm_info_type() const{
	return n2_sm_info_type;
}

//-----------------------------------------------------------------------------
void pdu_session_update_sm_context_request::set_n2_sm_info_type(std::string const& value){
	n2_sm_info_type = value;
}




