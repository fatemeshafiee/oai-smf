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

/*! \file smf_msg.hpp
  \brief
  \author
  \company Eurecom
  \email:
 */
#include "smf_msg.hpp"


using namespace pgwc;

supi_t pdu_session_create_sm_context_request::get_supi() const
{
	return m_Supi;
}
void pdu_session_create_sm_context_request::set_supi(supi_t const& value)
{
	m_Supi = value;
}

int32_t pdu_session_create_sm_context_request::get_pdu_sessionId() const
{

}
void pdu_session_create_sm_context_request::set_pdu_sessionId(int32_t const value)
{

}

std::string pdu_session_create_sm_context_request::get_dnn() const
{
	return m_Dnn;
}
void pdu_session_create_sm_context_request::set_dnn(std::string const& value)
{
	m_Dnn = value;
}

snssai_t pdu_session_create_sm_context_request::get_snssai() const
{
	return m_SNssai;
}
void pdu_session_create_sm_context_request::set_snssai(snssai_t const& value)
{
	m_SNssai = value;
}

std::string pdu_session_create_sm_context_request::get_serving_nfId() const
{
	return m_ServingNfId;
}
void pdu_session_create_sm_context_request::set_serving_nfId(std::string const& value)
{

}

std::string pdu_session_create_sm_context_request::get_request_type() const
{

}
void pdu_session_create_sm_context_request::set_request_type(std::string const& value)
{

}

pdu_session_establishment_request_msg pdu_session_create_sm_context_request::get_nas_msg() const
{
	return nas_msg;

}
void pdu_session_create_sm_context_request::set_nas_msg(pdu_session_establishment_request_msg const& value)
{
	nas_msg = value;
}

void pdu_session_create_sm_context_request::set_dnn_selection_mode (std::string const& value)
{
	m_SelMode = value;
}
std::string pdu_session_create_sm_context_request::get_dnn_selection_mode () const
{
	return m_SelMode;
}

uint8_t pdu_session_create_sm_context_request::get_pdu_session_type ()
{
	return (uint8_t)nas_msg._pdusessiontype;
}



void pdu_session_create_sm_context_response::set_cause(uint8_t cause)
{
	m_cause = cause;
}
uint8_t pdu_session_create_sm_context_response::get_cause(){
	return m_cause;
}

void pdu_session_create_sm_context_response::set_paa(paa_t paa)
{
	m_paa = paa;
}
paa_t pdu_session_create_sm_context_response::get_paa()
{
	return m_paa;
}


Pistache::Http::ResponseWriter& pdu_session_create_sm_context_response::get_http_response()
{
	return m_http_response;

}


