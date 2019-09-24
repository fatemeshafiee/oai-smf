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
#ifndef FILE_SMF_MSG_HPP_SEEN
#define FILE_SMF_MSG_HPP_SEEN

#include "smf.h"
//#include "pistache/endpoint.h"
#include "pistache/http.h"
//#include "pistache/router.h"

extern "C" {
#include "PDUSessionEstablishmentRequest.h"
}

namespace pgwc {


class pdu_session_create_sm_context_request {

public:
	pdu_session_create_sm_context_request(): nas_msg(), m_Supi(), m_UnauthenticatedSupi(true), m_PduSessionId(), m_Dnn(), m_SNssai() {}
	supi_t get_supi() const;
	void set_supi(supi_t const& value);

	int32_t get_pdu_sessionId() const;
	void set_pdu_sessionId(int32_t const value);

	std::string get_dnn() const;
	void set_dnn(std::string const& value);

	snssai_t get_snssai() const;
	void set_snssai(snssai_t const& value);

	std::string get_serving_nfId() const;
	void set_serving_nfId(std::string const& value);

	std::string get_request_type() const;
	void set_request_type(std::string const& value);

	pdu_session_establishment_request_msg get_nas_msg() const;
	void set_nas_msg(pdu_session_establishment_request_msg const& value);

	void set_dnn_selection_mode (std::string const& value);
	std::string get_dnn_selection_mode () const;

	uint8_t get_pdu_session_type ();


private:
	pdu_session_establishment_request_msg nas_msg;
	supi_t m_Supi;
	bool m_UnauthenticatedSupi;
	//std::string m_Pei;
	//std::string m_Gpsi;
	int32_t m_PduSessionId;
	std::string m_Dnn;
	snssai_t m_SNssai;
	//Snssai m_HplmnSnssai;
	std::string m_ServingNfId; //AMF Id
	//Guami m_Guami;
	//std::string m_ServiceName;
	//PlmnId m_ServingNetwork;
	std::string m_RequestType;
	//RefToBinaryData m_N1SmMsg;
	std::string m_AnType;
	//std::string m_SecondAnType;
	std::string m_RatType;
	std::string m_PresenceInLadn;
	//UserLocation m_UeLocation;
	//std::string m_UeTimeZone;
	//UserLocation m_AddUeLocation;
	//std::string m_SmContextStatusUri;

	//std::string m_HSmfUri;
	// std::vector<std::string> m_AdditionalHsmfUri;
	// int32_t m_OldPduSessionId;
	// std::vector<int32_t> m_PduSessionsActivateList;
	//std::string m_UeEpsPdnConnection;
	//std::string m_HoState;
	//std::string m_PcfId;
	//std::string m_NrfUri;
	//std::string m_SupportedFeatures;
	std::string m_SelMode;
	//std::vector<BackupAmfInfo> m_BackupAmfInfo;
	//TraceData m_TraceData;
	//std::string m_UdmGroupId;
	//std::string m_RoutingIndicator;
	//EpsInterworkingIndication m_EpsInterworkingInd;
	//bool m_IndirectForwardingFlag;
	//NgRanTargetId m_TargetId;
	//std::string m_EpsBearerCtxStatus;
	//bool m_CpCiotEnabled;
	//bool m_InvokeNef;
	// bool m_MaPduIndication;
	//RefToBinaryData m_N2SmInfo;
	std::string m_SmContextRef;
};




class pdu_session_create_sm_context_response {

public:
	pdu_session_create_sm_context_response(Pistache::Http::ResponseWriter& http_response): m_http_response(http_response) {}
    void set_cause(uint8_t cause);
    uint8_t get_cause();
    void set_paa(paa_t paa);
    paa_t get_paa();
    Pistache::Http::ResponseWriter& get_http_response();

private:
    uint8_t m_cause;
    paa_t m_paa;
    Pistache::Http::ResponseWriter& m_http_response;

};

}

#endif
