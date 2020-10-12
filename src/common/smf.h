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

#ifndef FILE_SMF_SEEN
#define FILE_SMF_SEEN

#include"3gpp_29.274.h"
#include"3gpp_29.571.h"
#include"3gpp_24.501.h"

typedef uint64_t supi64_t;
#define SUPI_64_FMT     "%" SCNu64

#define SUPI_DIGITS_MAX 15

typedef struct {
  uint32_t length;
  char data[SUPI_DIGITS_MAX + 1];
} supi_t;

static void smf_string_to_supi(supi_t *const supi, char const *const supi_str) {
  //strncpy(supi->data, supi_str, SUPI_DIGITS_MAX + 1);
  memcpy((void*) supi->data, (void*) supi_str, SUPI_DIGITS_MAX + 1);
  supi->length = strlen(supi->data);
  return;
}

static std::string smf_supi_to_string(supi_t const supi) {
  std::string supi_str;
  supi_str.assign(supi.data, SUPI_DIGITS_MAX + 1);
  return supi_str;
}

static uint64_t smf_supi_to_u64(supi_t supi) {
  uint64_t uint_supi;
  sscanf(supi.data, "%" SCNu64, &uint_supi);
  return uint_supi;
}

typedef struct s_nssai  // section 28.4, TS23.003
{
  uint8_t sST;
  //uint32_t sD:24;
  std::string sD;
  //s_nssai(const uint8_t& sst,  const uint32_t sd) : sST(sst), sD(sd) {}
  s_nssai(const uint8_t &sst, const std::string sd)
      :
      sST(sst),
      sD(sd) {
  }
  s_nssai()
      :
      sST(),
      sD() {
  }
  s_nssai(const s_nssai &p)
      :
      sST(p.sST),
      sD(p.sD) {
  }
  bool operator==(const struct s_nssai &s) const {
    if ((s.sST == this->sST) && (s.sD.compare(this->sD) == 0)) {
      return true;
    } else {
      return false;
    }
  }

} snssai_t;

typedef uint8_t pdu_session_id;

//SMF + AMF + 3GPP TS 29.571 (Common data)
enum class http_response_codes_e {
  HTTP_RESPONSE_CODE_OK = 200,
  HTTP_RESPONSE_CODE_ACCEPTED = 202,
  HTTP_RESPONSE_CODE_BAD_REQUEST = 400,
  HTTP_RESPONSE_CODE_UNAUTHORIZED = 401,
  HTTP_RESPONSE_CODE_FORBIDDEN = 403,
  HTTP_RESPONSE_CODE_NOT_FOUND = 404,
  HTTP_RESPONSE_CODE_METHOD_NOT_ALLOWED = 405,
  HTTP_RESPONSE_CODE_REQUEST_TIMEOUT = 408,
  HTTP_RESPONSE_CODE_406_NOT_ACCEPTED = 406,
  HTTP_RESPONSE_CODE_CONFLICT = 409,
  HTTP_RESPONSE_CODE_GONE = 410,
  HTTP_RESPONSE_CODE_LENGTH_REQUIRED = 411,
  HTTP_RESPONSE_CODE_PRECONDITION_FAILED = 412,
  HTTP_RESPONSE_CODE_PAYLOAD_TOO_LARGE = 413,
  HTTP_RESPONSE_CODE_URI_TOO_LONG = 414,
  HTTP_RESPONSE_CODE_UNSUPPORTED_MEDIA_TYPE = 415,
  HTTP_RESPONSE_CODE_TOO_MANY_REQUESTS = 429,
  HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR = 500,
  HTTP_RESPONSE_CODE_NOT_IMPLEMENTED = 501,
  HTTP_RESPONSE_CODE_SERVICE_UNAVAILABLE = 503,
  HTTP_RESPONSE_CODE_GATEWAY_TIMEOUT = 504

};

//From 23.502
enum class session_management_procedures_type_e {
  PROCEDURE_TYPE_UNKNOWN = 0,
  PDU_SESSION_ESTABLISHMENT_UE_REQUESTED = 1,
  SERVICE_REQUEST_UE_TRIGGERED_STEP1 = 2,
  SERVICE_REQUEST_UE_TRIGGERED_STEP2 = 3,
  SERVICE_REQUEST_NETWORK_TRIGGERED = 4,
  PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1 = 5,
  PDU_SESSION_MODIFICATION_UE_INITIATED_STEP2 = 6,
  PDU_SESSION_MODIFICATION_UE_INITIATED_STEP3 = 7,
  PDU_SESSION_MODIFICATION_SMF_REQUESTED = 8,
  PDU_SESSION_MODIFICATION_AN_REQUESTED = 9,
  PDU_SESSION_RELEASE_UE_REQUESTED_STEP1 = 10,
  PDU_SESSION_RELEASE_UE_REQUESTED_STEP2 = 11,
  PDU_SESSION_RELEASE_UE_REQUESTED_STEP3 = 12,
  PDU_SESSION_RELEASE_SMF_INITIATED = 13,
  PDU_SESSION_RELEASE_AMF_INITIATED = 14,
  PDU_SESSION_RELEASE_AN_INITIATED = 15,
  PDU_SESSION_TEST = 16
};

static const std::vector<std::string> session_management_procedures_type_e2str =
    { "PDU_SESSION_ESTABLISHMENT_UE_REQUESTED",
        "SERVICE_REQUEST_UE_TRIGGERED_STEP1",
        "SERVICE_REQUEST_UE_TRIGGERED_STEP2",
        "SERVICE_REQUEST_NETWORK_TRIGGERED",
        "PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1",
        "PDU_SESSION_MODIFICATION_UE_INITIATED_STEP2",
        "PDU_SESSION_MODIFICATION_UE_INITIATED_STEP3",
        "PDU_SESSION_MODIFICATION_SMF_REQUESTED",
        "PDU_SESSION_MODIFICATION_AN_REQUESTED",
        "PDU_SESSION_RELEASE_UE_REQUESTED_STEP1",
        "PDU_SESSION_RELEASE_UE_REQUESTED_STEP2",
        "PDU_SESSION_RELEASE_UE_REQUESTED_STEP3",
        "PDU_SESSION_RELEASE_SMF_INITIATED",
        "PDU_SESSION_RELEASE_AMF_INITIATED", "PDU_SESSION_RELEASE_AN_INITIATED",
        "PDU_SESSION_TEST"

    };

enum class sm_context_status_e {
  SM_CONTEXT_STATUS_ACTIVE = 0,
  SM_CONTEXT_STATUS_RELEASED = 1
};

static const std::vector<std::string> sm_context_status_e2str =
    { "ACTIVE",
      "RELEASED"
    };

typedef struct qos_profile_gbr_s {
  gfbr_t gfbr;  //Guaranteed Flow Bit Rate
  mfbr_t mfbr;  // Maximum Flow Bit Rate
  // Notification Control
  // Maximum Packet Loss Rate (UL/DL)
} qos_profile_gbr_t;

enum class qos_profile_type_e {
  NON_GBR = 0,
  GBR = 1
};

//See Section 5.7.2@3GPP TS 23.501
typedef struct qos_profile_s {
  uint8_t _5qi;
  arp_5gc_t arp;
  uint8_t priority_level;
  qos_profile_type_e profile_type;
  union {
    reflective_qos_attribute_e rqa;  //Reflective QoS Attribute (RQA)
    qos_profile_gbr_t qos_profile_gbr;  //Attributes for GBR
  } parameter;
} qos_profile_t;

//URL, N1, N2 (may get from configuration file)
#define NAMF_COMMUNICATION_BASE                       "/namf-comm/"
#define NAMF_COMMUNICATION_N1N2_MESSAGE_TRANSFER_URL  "/ue-contexts/{}/n1-n2-messages" //context id
#define NUDM_SDM_BASE                                 "/nudm-sdm/"
#define NUDM_SDM_GET_SM_DATA_URL                      "/{}/sm-data" //ue Id
#define N1_SM_CONTENT_ID                              "n1SmMsg"
#define N1N2_MESSAGE_CLASS                            "SM"
#define N2_SM_CONTENT_ID                              "n2msg"
#define NSMF_PDU_SESSION_BASE                         "/nsmf-pdusession/"
#define NSMF_CALLBACK_N1N2_MESSAGE_TRANSFER_FAILURE   "/callback/N1N2MsgTxfrFailureNotification/{}" //UE Id
#define NSMF_PDU_SESSION_SM_CONTEXT_CREATE_URL        "/sm-contexts"
#define NSMF_PDU_SESSION_SM_CONTEXT_UPDATE_URL        "/sm-contexts/"


//for CURL
#define AMF_CURL_TIMEOUT_MS 100L
#define AMF_NUMBER_RETRIES 3
#define UDM_CURL_TIMEOUT_MS 100L
#define UDM_NUMBER_RETRIES 3
constexpr auto CURL_MIME_BOUNDARY = "----Boundary";

//for N1N2
#define BUF_LEN 512

//for PFCP
constexpr uint64_t SECONDS_SINCE_FIRST_EPOCH = 2208988800;



#endif
