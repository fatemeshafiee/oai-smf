#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <unistd.h>
#include <stdexcept>
#include <thread>

#ifndef CURLPIPE_MULTIPLEX
#define CURLPIPE_MULTIPLEX 0
#endif

#define HTTP_V1 1
#define HTTP_V2 2

#define HTTP_CODE_OK 200
#define HTTP_CODE_CREATED 201
/*
 * To read content of the response from UDM
 */
static std::size_t callback(const char *in, std::size_t size, std::size_t num,
                            std::string *out) {
  const std::size_t totalBytes(size * num);
  out->append(in, totalBytes);
  return totalBytes;
}

#define ENCODE_U8(buffer, value, size)    \
    *(uint8_t*)(buffer) = value;    \
    size += sizeof(uint8_t)

static const char hex_to_ascii_table[16] = { '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', };

static const signed char ascii_to_hex_table[0x100] = { -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1,
    10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1 };

int ascii_to_hex(uint8_t *dst, const char *h) {
  const unsigned char *hex = (const unsigned char*) h;
  unsigned i = 0;

  for (;;) {
    int high, low;

    while (*hex && isspace(*hex))
      hex++;

    if (!*hex)
      return 1;

    high = ascii_to_hex_table[*hex++];

    if (high < 0)
      return 0;

    while (*hex && isspace(*hex))
      hex++;

    if (!*hex)
      return 0;

    low = ascii_to_hex_table[*hex++];

    if (low < 0)
      return 0;

    dst[i++] = (high << 4) | low;
  }
}

enum class multipart_related_content_part_e {
  JSON = 0,
  NAS = 1,
  NGAP = 2
};

//------------------------------------------------------------------------------
unsigned char* format_string_as_hex(std::string str) {
  unsigned int str_len = str.length();
  char *data = (char*) malloc(str_len + 1);
  memset(data, 0, str_len + 1);
  memcpy((void*) data, (void*) str.c_str(), str_len);

  unsigned char *data_hex = (uint8_t*) malloc(str_len / 2 + 1);
  ascii_to_hex(data_hex, (const char*) data);

  std::cout << "[Format string as Hex] Input string" << str.c_str() << "("
            << str_len << " bytes)" << std::endl;
  std::cout << "Data (formatted):" << std::endl;

  for (int i = 0; i < str_len / 2; i++)
    printf(" %02x ", data_hex[i]);
  printf("\n");

  //free memory
  free(data);

  return data_hex;

}

//------------------------------------------------------------------------------
void create_multipart_related_content(std::string &body, std::string &json_part,
                                      std::string &boundary,
                                      std::string &n1_message,
                                      std::string &n2_message) {

  std::string CRLF = "\r\n";
  body.append("--" + boundary + CRLF);
  body.append("Content-Type: application/json" + CRLF);
  body.append(CRLF);
  body.append(json_part + CRLF);

  body.append("--" + boundary + CRLF);
  body.append(
      "Content-Type: application/vnd.3gpp.5gnas" + CRLF + "Content-Id: n1SmMsg"
          + CRLF);
  body.append(CRLF);
  body.append(n1_message + CRLF);

  body.append("--" + boundary + CRLF);
  body.append(
      "Content-Type: application/vnd.3gpp.ngap" + CRLF + "Content-Id: n2msg"
          + CRLF);
  body.append(CRLF);
  body.append(n2_message + CRLF);
  body.append("--" + boundary + "--" + CRLF);
}

//------------------------------------------------------------------------------
void create_multipart_related_content(
    std::string &body, std::string &json_part, std::string &boundary,
    std::string &message, multipart_related_content_part_e content_type) {

  std::string CRLF = "\r\n";
  body.append("--" + boundary + CRLF);
  body.append("Content-Type: application/json" + CRLF);
  body.append(CRLF);
  body.append(json_part + CRLF);

  body.append("--" + boundary + CRLF);
  if (content_type == multipart_related_content_part_e::NAS) {  //NAS
    body.append(
        "Content-Type: application/vnd.3gpp.5gnas" + CRLF
            + "Content-Id: n1SmMsg" + CRLF);
  } else if (content_type == multipart_related_content_part_e::NGAP) {  //NGAP
    body.append(
        "Content-Type: application/vnd.3gpp.ngap" + CRLF + "Content-Id: n2msg"
            + CRLF);
  }
  body.append(CRLF);
  body.append(message + CRLF);
  body.append("--" + boundary + "--" + CRLF);
}

//------------------------------------------------------------------------------
bool send_pdu_session_establishment_request(uint8_t pid,
                                            std::string smf_ip_address,
                                            uint8_t http_version,
                                            std::string port) {
  //TODO: return the created SM context Id
  std::cout << "[AMF N11] PDU Session Establishment Request (SM Context Create)"
            << std::endl;
  // Response information.
  long httpCode = { 0 };

  nlohmann::json pdu_session_establishment_request;
  //encode PDU Session Establishment Request
  /*
   0000   2e 01 01 c1 ff ff 91 00 00 00 00 00 00 00 00 00
   */
  size_t buffer_size = 128;
  char *buffer = (char*) calloc(1, buffer_size);
  int size = 0;
  ENCODE_U8(buffer, 0x2e, size);  //ExtendedProtocolDiscriminator
  ENCODE_U8(buffer + size, pid, size);  //PDUSessionIdentity
  ENCODE_U8(buffer + size, 0x01, size);  //ProcedureTransactionIdentity
  ENCODE_U8(buffer + size, 0xc1, size);  //MessageType - PDU_SESSION_ESTABLISHMENT_REQUEST
  ENCODE_U8(buffer + size, 0xff, size);  //Integrity Protection Maximum Data Rate
  ENCODE_U8(buffer + size, 0xff, size);  //Integrity Protection Maximum Data Rate
  ENCODE_U8(buffer + size, 0x91, size);  //01 PDU Session Type - Ipv4

  std::cout << "Buffer: " << std::endl;
  for (int i = 0; i < size; i++) {
    printf("%02x ", buffer[i]);
  }
  std::cout << "Buffer: " << std::endl;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    url.append(std::string(":"));
    url.append(port);
  }
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts"));

  //Fill the json part
  pdu_session_establishment_request["supi"] = "imsi-200000000000001";
  pdu_session_establishment_request["pei"] = "imei-200000000000001";
  pdu_session_establishment_request["gpsi"] = "msisdn-200000000001";
  pdu_session_establishment_request["dnn"] = "default";
  pdu_session_establishment_request["sNssai"]["sst"] = 222;
  pdu_session_establishment_request["sNssai"]["sd"] = "0000D4";
  pdu_session_establishment_request["pduSessionId"] = pid;
  pdu_session_establishment_request["requestType"] = "INITIAL_REQUEST";
  pdu_session_establishment_request["servingNfId"] = "servingNfId";
  pdu_session_establishment_request["servingNetwork"]["mcc"] = "234";
  pdu_session_establishment_request["servingNetwork"]["mnc"] = "067";
  pdu_session_establishment_request["anType"] = "3GPP_ACCESS";
  pdu_session_establishment_request["smContextStatusUri"] =
      "smContextStatusUri";
  pdu_session_establishment_request["n1SmMsg"]["contentId"] = "n1SmMsg";  // NAS

  std::string body;
  std::string boundary = "----Boundary";
  std::string json_part = pdu_session_establishment_request.dump();
  std::string n1_msg(reinterpret_cast<const char*>(buffer), size);

  create_multipart_related_content(body, json_part, boundary, n1_msg,
                                   multipart_related_content_part_e::NAS);

  unsigned char *data = (unsigned char*) malloc(body.length() + 1);
  memset(data, 0, body.length() + 1);
  memcpy((void*) data, (void*) body.c_str(), body.length());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
    }
    std::cout
        << "[AMF N11] PDU session establishment request, response from SMF "
        << response_data.dump().c_str() << ", Http Code " << httpCode
        << std::endl;
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  free(buffer);

  if (httpCode == HTTP_CODE_CREATED) {
    return true;
  } else {
    return false;
  }
}

//------------------------------------------------------------------------------
bool send_pdu_session_update_sm_context_establishment(
    uint8_t context_id, std::string smf_ip_address, uint8_t http_version,
    std::string port) {
  std::cout << "[AMF N11] PDU Session Establishment Request (SM Context Update)"
            << std::endl;

  // Response information.
  long httpCode = { 0 };

  nlohmann::json pdu_session_update_request;
  //encode PDU Session Resource Setup Response Transfer IE
  /*
   00 03 e0 ac 0a 05 01 00 00 00 01 00 06
   */
  size_t buffer_size = 128;
  char *buffer = (char*) calloc(1, buffer_size);
  int size = 0;
  ENCODE_U8(buffer, 0x00, size);
  ENCODE_U8(buffer + size, 0x03, size);
  ENCODE_U8(buffer + size, 0xe0, size);
  ENCODE_U8(buffer + size, 0xac, size);  //uPTransportLayerInformation IP Addr 172.16.3.103: 172.
  ENCODE_U8(buffer + size, 0x10, size);  //16
  ENCODE_U8(buffer + size, 0x03, size);  //.3
  ENCODE_U8(buffer + size, 0x67, size);  //.103
  ENCODE_U8(buffer + size, 0x00, size);  //gTP_TEID 00 00 00 01: 00
  ENCODE_U8(buffer + size, 0x00, size);  //00
  ENCODE_U8(buffer + size, 0x00, size);  //00
  ENCODE_U8(buffer + size, 0x01, size);  //01
  ENCODE_U8(buffer + size, 0x00, size);  //Associated QoS Flow 00 06
  ENCODE_U8(buffer + size, 0x06, size);  //QFI: 06

  std::cout << "Buffer: " << std::endl;
  for (int i = 0; i < size; i++) {
    printf("%02x ", buffer[i]);
  }
  std::cout << "Buffer: " << std::endl;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    //url.append(std::string(":9090"));
    url.append(std::string(":"));
    url.append(port);
  }
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/modify"));
//  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/modify"));

  //Fill the json part
  pdu_session_update_request["n2SmInfoType"] = "PDU_RES_SETUP_RSP";
  pdu_session_update_request["n2SmInfo"]["contentId"] = "n2msg";  //NGAP

  //pdu_session_update_request["n2InfoContainer"]["n2InformationClass"] = "SM";
  //pdu_session_update_request["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"] = "n2msg";
  // pdu_session_update_request["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] =
  //   "PDU_RES_SETUP_RSP";  //NGAP message

  std::string body;
  std::string boundary = "----Boundary";
  std::string json_part = pdu_session_update_request.dump();
  std::string n2_msg(reinterpret_cast<const char*>(buffer), size);

  create_multipart_related_content(body, json_part, boundary, n2_msg,
                                   multipart_related_content_part_e::NGAP);

  unsigned char *data = (unsigned char*) malloc(body.length() + 1);
  memset(data, 0, body.length() + 1);
  memcpy((void*) data, (void*) body.c_str(), body.length());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
      //Set the default Cause
      response_data["cause"] = "504 Gateway Timeout";

    }
    std::cout
        << "[AMF N11] PDU Session Establishment Request, response from SMF, Http Code "
        << httpCode << " cause  " << response_data["cause"].dump().c_str()
        << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  free(buffer);

  if (httpCode == HTTP_CODE_OK) {
    return true;
  } else {
    return false;
  }

}

//------------------------------------------------------------------------------
void send_pdu_session_modification_request_step1(uint8_t pid,
                                                 uint8_t context_id,
                                                 std::string smf_ip_address,
                                                 uint8_t http_version,
                                                 std::string port) {

  std::cout
      << "[AMF N11] PDU Session Modification Request (SM Context Update, Step 1)"
      << std::endl;

  nlohmann::json pdu_session_modification_request;
  //encode PDU Session Modification Request
  /*
   0000   2e 01 01 d1 00 00 00 00 00 00 00 00 00 00 00 00
   */
  size_t buffer_size = 128;
  char *buffer = (char*) calloc(1, buffer_size);
  int size = 0;
  ENCODE_U8(buffer, 0x2e, size);  //ExtendedProtocolDiscriminator
  ENCODE_U8(buffer + size, pid, size);  //PDUSessionIdentity
  ENCODE_U8(buffer + size, 0x01, size);  //ProcedureTransactionIdentity
  ENCODE_U8(buffer + size, 0xc9, size);  //MessageType - PDU Session Modification Request
  ENCODE_U8(buffer + size, 0x28, size);  //_5GSMCapability
  ENCODE_U8(buffer + size, 0x01, size);  //_5GSMCapability
  ENCODE_U8(buffer + size, 0x00, size);  //_5GSMCapability
  ENCODE_U8(buffer + size, 0x59, size);  //_5GSMCause
  ENCODE_U8(buffer + size, 0x00, size);  //_5GSMCause
  ENCODE_U8(buffer + size, 0x7a, size);  //QoS Rules IE
  ENCODE_U8(buffer + size, 0x00, size);  //QoS Rules length
  ENCODE_U8(buffer + size, 0x12, size);  //QoS Rules length
  ENCODE_U8(buffer + size, 0x01, size);  //QoS Rules rule id
  ENCODE_U8(buffer + size, 0x00, size);  //QoS Rules rule length
  ENCODE_U8(buffer + size, 0x06, size);  //QoS Rules rule length
  ENCODE_U8(buffer + size, 0x31, size);  //QoS Rules
  ENCODE_U8(buffer + size, 0x31, size);  //QoS Rules
  ENCODE_U8(buffer + size, 0x01, size);  //QoS Rules filter 1 length
  ENCODE_U8(buffer + size, 0x01, size);  //QoS Rules
  ENCODE_U8(buffer + size, 0x01, size);  //QoS Rules
  ENCODE_U8(buffer + size, 0x06, size);  //QoS Rules
  ENCODE_U8(buffer + size, 0x02, size);  //QoS Rules rule id
  ENCODE_U8(buffer + size, 0x00, size);  //QoS Rules rule length
  ENCODE_U8(buffer + size, 0x06, size);  //QoS Rules rule length
  ENCODE_U8(buffer + size, 0x21, size);  //QoS Rules
  ENCODE_U8(buffer + size, 0x31, size);  //QoS Rules
  ENCODE_U8(buffer + size, 0x01, size);  //QoS Rules filter 1 length
  ENCODE_U8(buffer + size, 0x01, size);  //QoS Rules
  ENCODE_U8(buffer + size, 0x01, size);  //QoS Rules
  ENCODE_U8(buffer + size, 0x06, size);  //QoS Rules

  std::cout << "Buffer: " << std::endl;
  for (int i = 0; i < size; i++) {
    printf("%02x ", buffer[i]);
  }
  std::cout << "Buffer: " << std::endl;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    //url.append(std::string(":9090"));
    url.append(std::string(":"));
    url.append(port);
  }
  //url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/modify"));
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/modify"));

  //Fill the json part
  pdu_session_modification_request["pduSessionId"] = pid;
  pdu_session_modification_request["n1SmMsg"]["contentId"] = "n1SmMsg";  // NAS

  std::string body;
  std::string boundary = "----Boundary";
  std::string json_part = pdu_session_modification_request.dump();
  std::string n1_msg(reinterpret_cast<const char*>(buffer), size);

  create_multipart_related_content(body, json_part, boundary, n1_msg,
                                   multipart_related_content_part_e::NAS);

  unsigned char *data = (unsigned char*) malloc(body.length() + 1);
  memset(data, 0, body.length() + 1);
  memcpy((void*) data, (void*) body.c_str(), body.length());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
    }
    std::cout
        << "[AMF N11] PDU Session Modification Request, response from SMF, Http Code "
        << httpCode << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  free(buffer);
}

//------------------------------------------------------------------------------
void send_pdu_session_modification_request_step2(uint8_t context_id,
                                                 std::string smf_ip_address,
                                                 uint8_t http_version,
                                                 std::string port) {

  std::cout
      << "[AMF N11] PDU Session Modification procedure (SM Context Update, step 2)"
      << std::endl;

  nlohmann::json pdu_session_modification;
  //encode PDU Session Resource Modify Response Transfer IE

  size_t buffer_size = 128;
  char *buffer = (char*) calloc(1, buffer_size);
  int size = 0;
  //ENCODE_U8(buffer, 0x00, size);
  ENCODE_U8(buffer + size, 0x50, size);
  ENCODE_U8(buffer + size, 0x03, size);
  ENCODE_U8(buffer + size, 0xe0, size);  //Id dL_NGU_UP_TNLInformation
  ENCODE_U8(buffer + size, 0xac, size);  //Transport Layer Address 172.16.3.101: 172
  ENCODE_U8(buffer + size, 0x10, size);  //Transport Layer Address 172.16.3.101: 16
  ENCODE_U8(buffer + size, 0x03, size);  //Transport Layer Address 172.16.3.101: 3
  ENCODE_U8(buffer + size, 0x65, size);  //Transport Layer Address 172.16.3.101: 101
  ENCODE_U8(buffer + size, 0x00, size);  //Gtp-teid: 01000000
  ENCODE_U8(buffer + size, 0x00, size);  //Gtp-teid: 01000000
  ENCODE_U8(buffer + size, 0x00, size);  //Gtp-teid: 01000000
  ENCODE_U8(buffer + size, 0x01, size);  //Gtp-teid: 01000000
  ENCODE_U8(buffer + size, 0x00, size);  //QoSFlowAddorModifyResponseList
  ENCODE_U8(buffer + size, 0x0c, size);  //60: QFI

  std::cout << "Buffer: " << std::endl;
  for (int i = 0; i < size; i++) {
    printf("%02x ", buffer[i]);
  }
  std::cout << "Buffer: " << std::endl;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    //url.append(std::string(":9090"));
    url.append(std::string(":"));
    url.append(port);
  }
  // url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/modify"));
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/modify"));

  //Fill the json part
  pdu_session_modification["n2SmInfoType"] = "PDU_RES_MOD_RSP";  //"PDU_RES_SETUP_RSP"
  pdu_session_modification["n2SmInfo"]["contentId"] = "n2msg";  //NGAP

  std::string body;
  std::string boundary = "----Boundary";
  std::string json_part = pdu_session_modification.dump();
  std::string n2_msg(reinterpret_cast<const char*>(buffer), size);

  create_multipart_related_content(body, json_part, boundary, n2_msg,
                                   multipart_related_content_part_e::NGAP);

  unsigned char *data = (unsigned char*) malloc(body.length() + 1);
  memset(data, 0, body.length() + 1);
  memcpy((void*) data, (void*) body.c_str(), body.length());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
    }
    std::cout
        << "[AMF N11] PDU Session Modification procedure (step 2), response from SMF, Http Code "
        << httpCode << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  free(buffer);
}

//------------------------------------------------------------------------------
void send_pdu_session_modification_complete(uint8_t pid, uint8_t context_id,
                                            std::string smf_ip_address,
                                            uint8_t http_version,
                                            std::string port) {

  std::cout
      << "[AMF N11] PDU Session Modification Complete (Update SM Context): N1 SM - PDU Session Modification Complete"
      << std::endl;

  nlohmann::json pdu_session_modification_complete;
  //encode PDU Session Modification Complete
  size_t buffer_size = 128;
  char *buffer = (char*) calloc(1, buffer_size);
  int size = 0;
  ENCODE_U8(buffer, 0x2e, size);  //ExtendedProtocolDiscriminator
  ENCODE_U8(buffer + size, pid, size);  //PDUSessionIdentity
  ENCODE_U8(buffer + size, 0x01, size);  //ProcedureTransactionIdentity
  ENCODE_U8(buffer + size, 0xcc, size);  //MessageType
  ENCODE_U8(buffer + size, 0x00, size);  //presence
  ENCODE_U8(buffer + size, 0x00, size);  //Extended protocol configuration options

  std::cout << "Buffer: " << std::endl;
  for (int i = 0; i < size; i++) {
    printf("%02x ", buffer[i]);
  }
  std::cout << "Buffer: " << std::endl;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    //url.append(std::string(":9090"));
    url.append(std::string(":"));
    url.append(port);
  }
//  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/modify"));
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/modify"));

  //Fill the json part
  pdu_session_modification_complete["n1SmMsg"]["contentId"] = "n1SmMsg";  // NAS

  std::string body;
  std::string boundary = "----Boundary";
  std::string json_part = pdu_session_modification_complete.dump();
  std::string n1_msg(reinterpret_cast<const char*>(buffer), size);

  create_multipart_related_content(body, json_part, boundary, n1_msg,
                                   multipart_related_content_part_e::NAS);

  unsigned char *data = (unsigned char*) malloc(body.length() + 1);
  memset(data, 0, body.length() + 1);
  memcpy((void*) data, (void*) body.c_str(), body.length());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
    }
    std::cout
        << "[AMF N11] PDU Session Modification Complete, response from SMF, Http Code "
        << httpCode << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  free(buffer);
}

//------------------------------------------------------------------------------
void send_pdu_session_release_request(uint8_t pid, uint8_t context_id,
                                      std::string smf_ip_address,
                                      uint8_t http_version, std::string port) {

  std::cout << "[AMF N11] PDU Session Release Request (SM Context Update)"
            << std::endl;

  nlohmann::json pdu_session_release_request;
  //encode PDU Session Release Request
  /*
   0000   2e 01 01 d1 00 00 00 00 00 00 00 00 00 00 00 00
   */
  size_t buffer_size = 128;
  char *buffer = (char*) calloc(1, buffer_size);
  int size = 0;
  ENCODE_U8(buffer, 0x2e, size);  //ExtendedProtocolDiscriminator
  ENCODE_U8(buffer + size, pid, size);  //PDUSessionIdentity
  ENCODE_U8(buffer + size, 0x01, size);  //ProcedureTransactionIdentity
  ENCODE_U8(buffer + size, 0xd1, size);  //MessageType
  ENCODE_U8(buffer + size, 0x00, size);  //presence

  std::cout << "Buffer: " << std::endl;
  for (int i = 0; i < size; i++) {
    printf("%02x ", buffer[i]);
  }
  std::cout << "Buffer: " << std::endl;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    //url.append(std::string(":9090"));
    url.append(std::string(":"));
    url.append(port);
  }
  //url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/modify"));
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/modify"));

  //Fill the json part
  pdu_session_release_request["cause"] = "INSUFFICIENT_UP_RESOURCES";  //need to be updated
  pdu_session_release_request["n1SmMsg"]["contentId"] = "n1SmMsg";  // NAS

  std::string body;
  std::string boundary = "----Boundary";
  std::string json_part = pdu_session_release_request.dump();
  std::string n1_msg(reinterpret_cast<const char*>(buffer), size);

  create_multipart_related_content(body, json_part, boundary, n1_msg,
                                   multipart_related_content_part_e::NAS);

  unsigned char *data = (unsigned char*) malloc(body.length() + 1);
  memset(data, 0, body.length() + 1);
  memcpy((void*) data, (void*) body.c_str(), body.length());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
    }
    std::cout
        << "[AMF N11] PDU Session Release Request, response from SMF, Http Code "
        << httpCode << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  free(buffer);
}

//------------------------------------------------------------------------------
void send_pdu_session_release_resource_release_ack(uint8_t context_id,
                                                   std::string smf_ip_address,
                                                   uint8_t http_version,
                                                   std::string port) {

  std::cout
      << "[AMF N11] PDU Session Release Ack (Update SM Context): N2 SM - Resource Release Ack"
      << std::endl;

  nlohmann::json pdu_session_release_ack;
  //encode PDU Session Resource Release Response Transfer IE
  size_t buffer_size = 128;
  char *buffer = (char*) calloc(1, buffer_size);
  int size = 0;
  ENCODE_U8(buffer, 0x00, size);

  std::cout << "Buffer: " << std::endl;
  for (int i = 0; i < size; i++) {
    printf("%02x ", buffer[i]);
  }
  std::cout << "Buffer: " << std::endl;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    //url.append(std::string(":9090"));
    url.append(std::string(":"));
    url.append(port);
  }
//  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/modify"));
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/modify"));

  //Fill the json part
  pdu_session_release_ack["n2SmInfoType"] = "PDU_RES_REL_RSP";
  pdu_session_release_ack["n2SmInfo"]["contentId"] = "n2msg";  //NGAP

  std::string body;
  std::string boundary = "----Boundary";
  std::string json_part = pdu_session_release_ack.dump();
  std::string n2_msg(reinterpret_cast<const char*>(buffer), size);

  create_multipart_related_content(body, json_part, boundary, n2_msg,
                                   multipart_related_content_part_e::NGAP);

  unsigned char *data = (unsigned char*) malloc(body.length() + 1);
  memset(data, 0, body.length() + 1);
  memcpy((void*) data, (void*) body.c_str(), body.length());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;

    }
    std::cout
        << "[AMF N11] PDU Session Release Ack, response from SMF, Http Code "
        << httpCode << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  free(buffer);
}

//------------------------------------------------------------------------------
void send_pdu_session_release_complete(uint8_t pid, uint8_t context_id,
                                       std::string smf_ip_address,
                                       uint8_t http_version, std::string port) {

  std::cout
      << "[AMF N11] PDU Session Release Complete (Update SM Context): N1 SM - PDU Session Release Complete"
      << std::endl;

  nlohmann::json pdu_session_release_complete;
  //encode PDU Session Release Complete
  /*
   0000   2e 01 01 c1 d4 00 00 00 00 00 00 00 00 00 00 00
   */
  size_t buffer_size = 128;
  char *buffer = (char*) calloc(1, buffer_size);
  int size = 0;
  ENCODE_U8(buffer, 0x2e, size);  //ExtendedProtocolDiscriminator
  ENCODE_U8(buffer + size, pid, size);  //PDUSessionIdentity
  ENCODE_U8(buffer + size, 0x01, size);  //ProcedureTransactionIdentity
  ENCODE_U8(buffer + size, 0xd4, size);  //MessageType
  ENCODE_U8(buffer + size, 0x00, size);  //Cause
  ENCODE_U8(buffer + size, 0x00, size);  //Extended protocol configuration options

  std::cout << "Buffer: " << std::endl;
  for (int i = 0; i < size; i++) {
    printf("%02x ", buffer[i]);
  }
  std::cout << "Buffer: " << std::endl;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    //url.append(std::string(":9090"));
    url.append(std::string(":"));
    url.append(port);
  }
  //url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/modify"));
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/modify"));

  //Fill the json part
  pdu_session_release_complete["cause"] = "INSUFFICIENT_UP_RESOURCES";  //need to be updated
  pdu_session_release_complete["n1SmMsg"]["contentId"] = "n1SmMsg";  // NAS

  std::string body;
  std::string boundary = "----Boundary";
  std::string json_part = pdu_session_release_complete.dump();
  std::string n1_msg(reinterpret_cast<const char*>(buffer), size);

  create_multipart_related_content(body, json_part, boundary, n1_msg,
                                   multipart_related_content_part_e::NAS);

  unsigned char *data = (unsigned char*) malloc(body.length() + 1);
  memset(data, 0, body.length() + 1);
  memcpy((void*) data, (void*) body.c_str(), body.length());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
    }
    std::cout
        << "[AMF N11] PDU Session Release Complete, response from SMF, Http Code "
        << httpCode << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  free(buffer);
}

//------------------------------------------------------------------------------
void send_pdu_session_update_sm_context_ue_service_request(
    uint8_t context_id, std::string smf_ip_address, uint8_t http_version,
    std::string port) {
  std::cout
      << "[AMF N11] UE-triggered Service Request (SM Context Update Step 1)"
      << std::endl;

  nlohmann::json service_requests;
  //NO NAS, No NGAP

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    //url.append(std::string(":9090"));
    url.append(std::string(":"));
    url.append(port);
  }
  //url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/modify"));
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/modify"));

  //PDU session ID (as specified in section 4.2.3.2 @ 3GPP TS 23.502, but can't find in Yaml file)
  service_requests["upCnxState"] = "ACTIVATING";
  service_requests["ratType"] = "NR";
  service_requests["anType"] = "3GPP_ACCESS";

  std::string body;
  body = service_requests.dump();

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(headers, "content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get response from SMF
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
    }
    std::cout
        << "[AMF N11] UE Triggered Service Request (Step 1), response from SMF, Http Code "
        << httpCode << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

}

//------------------------------------------------------------------------------
void send_pdu_session_update_sm_context_ue_service_request_step2(
    uint8_t context_id, std::string smf_ip_address, uint8_t http_version,
    std::string port) {
  std::cout
      << "[AMF N11] UE-triggered Service Request (SM Context Update Step 2)"
      << std::endl;

  nlohmann::json service_requests;
  //encode PDU Session Resource Setup Response Transfer IE
  /*
   00 03 e0 ac 0a 05 01 00 00 00 01 00 06
   */
  size_t buffer_size = 128;
  char *buffer = (char*) calloc(1, buffer_size);
  int size = 0;
  ENCODE_U8(buffer, 0x00, size);
  ENCODE_U8(buffer + size, 0x03, size);
  ENCODE_U8(buffer + size, 0xe0, size);
  ENCODE_U8(buffer + size, 0xac, size);  //uPTransportLayerInformation IP Addr 172.10.5.1: 172.
  ENCODE_U8(buffer + size, 0x0a, size);  //10
  ENCODE_U8(buffer + size, 0x05, size);  //.5
  ENCODE_U8(buffer + size, 0x01, size);  //.1
  ENCODE_U8(buffer + size, 0x00, size);  //gTP_TEID 00 00 00 01: 00
  ENCODE_U8(buffer + size, 0x00, size);  //00
  ENCODE_U8(buffer + size, 0x00, size);  //00
  ENCODE_U8(buffer + size, 0x01, size);  //01
  ENCODE_U8(buffer + size, 0x00, size);  //Associated QoS Flow 00 06
  ENCODE_U8(buffer + size, 0x06, size);  //QFI: 06

  std::cout << "Buffer: " << std::endl;
  for (int i = 0; i < size; i++) {
    printf("%02x ", buffer[i]);
  }
  std::cout << "Buffer: " << std::endl;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    //url.append(std::string(":9090"));
    url.append(std::string(":"));
    url.append(port);
  }
  //url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/modify"));
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/modify"));

  //Fill the json part
  service_requests["n2SmInfoType"] = "PDU_RES_SETUP_RSP";
  service_requests["n2SmInfo"]["contentId"] = "n2msg";  //NGAP

  //service_requests["n2InfoContainer"]["n2InformationClass"] = "SM";
  //service_requests["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapData"]["contentId"] = "n2msg";
  // service_requests["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"] =
  //   "PDU_RES_SETUP_RSP";  //NGAP message

  service_requests["anType"] = "3GPP_ACCESS";
  service_requests["ratType"] = "NR";

  std::string body;
  std::string boundary = "----Boundary";
  std::string json_part = service_requests.dump();
  std::string n2_msg(reinterpret_cast<const char*>(buffer), size);

  create_multipart_related_content(body, json_part, boundary, n2_msg,
                                   multipart_related_content_part_e::NGAP);

  unsigned char *data = (unsigned char*) malloc(body.length() + 1);
  memset(data, 0, body.length() + 1);
  memcpy((void*) data, (void*) body.c_str(), body.length());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(
        headers, "content-type: multipart/related; boundary=----Boundary");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
      //Set the default Cause
      response_data["cause"] = "504 Gateway Timeout";

    }
    std::cout
        << "[AMF N11] UE Triggered Service Request (Step 2), response from SMF, Http Code "
        << httpCode << " cause  " << response_data["cause"].dump().c_str()
        << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

  free(buffer);
}

//------------------------------------------------------------------------------
void send_release_sm_context_request(uint8_t pid, uint8_t context_id,
                                     std::string smf_ip_address,
                                     uint8_t http_version, std::string port) {

  std::cout << "[AMF N11] PDU Session Release SM context Request" << std::endl;

  nlohmann::json send_release_sm_context_request;

  std::string url = std::string("http://");
  url.append(smf_ip_address);
  if (http_version == 2) {
    url.append(std::string(":"));
    url.append(port);
  }
  //url.append(std::string("/nsmf-pdusession/v1/sm-contexts/1/release"));
  url.append(std::string("/nsmf-pdusession/v1/sm-contexts/"));
  url.append(std::to_string(context_id));
  url.append(std::string("/release"));

  //Fill the json part
  send_release_sm_context_request["pduSessionId"] = pid;

  std::string body = send_release_sm_context_request.dump();

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = { };
    struct curl_slist *headers = nullptr;
    //headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(headers, "content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 100L);
    //curl_easy_setopt(curl, CURLOPT_INTERFACE, "eno1:amf");  //hardcoded

    if (http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      /* we use a self-signed test server, skip verification during debugging */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#if (CURLPIPE_MULTIPLEX > 0)
      /* wait for pipe connection to confirm */
      curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);
#endif
    }

    // Response information.
    long httpCode = { 0 };
    std::unique_ptr<std::string> httpData(new std::string());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());

    res = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    //get cause from the response
    nlohmann::json response_data;
    try {
      response_data = nlohmann::json::parse(*httpData.get());
    } catch (nlohmann::json::exception &e) {
      std::cout << "Could not get json data from the response" << std::endl;
    }
    std::cout
        << "[AMF N11] PDU Session Release SM Context Request, response from SMF, Http Code "
        << httpCode << std::endl;

    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();

}

//------------------------------------------------------------------------------
bool pdu_session_establishment(uint8_t pid, uint8_t context_id,
                               std::string smf_ip_address, uint8_t http_version,
                               std::string port) {

  bool status = false;
  if (send_pdu_session_establishment_request(pid, smf_ip_address, http_version,
                                             port)) {
    //usleep(100000);
    status = send_pdu_session_update_sm_context_establishment(context_id,
                                                              smf_ip_address,
                                                              http_version,
                                                              port);
  }
  return status;

}

//------------------------------------------------------------------------------
void test_all_procedures_for_one_session(uint8_t pid, uint8_t context_id,
                                         std::string smf_ip_address,
                                         uint8_t http_version,
                                         std::string port) {

  bool status = false;
  if (send_pdu_session_establishment_request(pid, smf_ip_address, http_version,
                                             port)) {
    usleep(100000);
    status = send_pdu_session_update_sm_context_establishment(context_id,
                                                              smf_ip_address,
                                                              http_version,
                                                              port);
  }

  if (status) {
    usleep(200000);
    //UE-initiated Service Request
    send_pdu_session_update_sm_context_ue_service_request(context_id,
                                                          smf_ip_address,
                                                          http_version, port);
    usleep(200000);
    send_pdu_session_update_sm_context_ue_service_request_step2(context_id,
                                                                smf_ip_address,
                                                                http_version,
                                                                port);
    usleep(200000);
    //PDU Session Modification
    send_pdu_session_modification_request_step1(pid, context_id, smf_ip_address,
                                                http_version, port);
    usleep(200000);
    send_pdu_session_modification_request_step2(context_id, smf_ip_address,
                                                http_version, port);
    usleep(200000);
    send_pdu_session_modification_complete(pid, context_id, smf_ip_address,
                                           http_version, port);
    usleep(200000);
    //PDU Session Release procedure
    send_pdu_session_release_request(pid, context_id, smf_ip_address,
                                     http_version, port);
    usleep(200000);
    send_pdu_session_release_resource_release_ack(context_id, smf_ip_address,
                                                  http_version, port);
    usleep(200000);
    send_pdu_session_release_complete(pid, context_id, smf_ip_address,
                                      http_version, port);
    usleep(200000);
    //Release SM context
    //send_release_sm_context_request(pid, smf_ip_address, http_version, port);
  }
}

//------------------------------------------------------------------------------
void test_session_establishment_multiple_threads(std::string smf_ip_address,
                                                 uint8_t http_version,
                                                 std::string port) {
  std::vector<std::thread> pdu_threads;

  for (int i = 0; i < 10; i++) {
    std::thread session_establishment(&pdu_session_establishment, i, i,
                                      smf_ip_address, http_version, port);

    pdu_threads.push_back(std::move(session_establishment));
  }

  for (auto &t : pdu_threads) {
    t.join();
  }

}

//------------------------------------------------------------------------------
void test_all_procedures_for_multiple_threads(std::string smf_ip_address,
                                              uint8_t http_version,
                                              std::string port) {
  uint8_t pid = 1;
  uint8_t context_id = 1;

  //bool status = false;

/*  std::thread t1(&send_pdu_session_establishment_request, pid, smf_ip_address,
                 http_version, port);
  std::thread t2(&send_pdu_session_update_sm_context_establishment, context_id,
                 smf_ip_address, http_version, port);
*/
  std::thread t1(&pdu_session_establishment, pid, context_id, smf_ip_address,
                  http_version, port);

  std::thread t3(&send_pdu_session_update_sm_context_ue_service_request,
                 context_id, smf_ip_address, http_version, port);
  std::thread t4(&send_pdu_session_update_sm_context_ue_service_request_step2,
                 context_id, smf_ip_address, http_version, port);
  std::thread t5(&send_pdu_session_modification_request_step1, pid, context_id,
                 smf_ip_address, http_version, port);
  std::thread t6(&send_pdu_session_modification_request_step2, context_id,
                 smf_ip_address, http_version, port);
  std::thread t7(&send_pdu_session_modification_complete, pid, context_id,
                 smf_ip_address, http_version, port);
  //PDU Session Release procedure
  std::thread t8(&send_pdu_session_release_request, pid, context_id,
                 smf_ip_address, http_version, port);
  std::thread t9(&send_pdu_session_release_resource_release_ack, context_id,
                 smf_ip_address, http_version, port);
  std::thread t10(&send_pdu_session_release_complete, pid, context_id,
                  smf_ip_address, http_version, port);

  //Release SM context
  //send_release_sm_context_request(pid, smf_ip_address, http_version, port);

  t1.join();
//  t2.join();
  t3.join();
  t4.join();
  t5.join();
  t6.join();
  t7.join();
  t8.join();
  t9.join();
  t10.join();

}

//------------------------------------------------------------------------------
int main(int argc, char *argv[]) {
  std::string smf_ip_address;
  uint8_t http_version = 1;
  std::string port;

  http_version = 1;
  port = std::string("80");

  if ((argc != 1) && (argc != 3) && (argc != 5) && (argc != 7)) {
    std::cout << "Error: Usage is " << std::endl;
    std::cout << "  " << argv[0] << " [ -i www.xxx.yy.zz -v 1 -p 9090]"
              << std::endl;
    return -1;
  }

  if (argc == 1) {
    smf_ip_address.append(std::string("192.168.28.2"));
  } else {
    int opt = 0;
    while ((opt = getopt(argc, argv, "i:v:p:")) != -1) {
      switch (opt) {
        case 'i':
          smf_ip_address.append(optarg);
          break;
        case 'v':
          http_version = std::stoi(optarg);
          break;
        case 'p':
          port = std::string(optarg);
          break;
        default:
          std::cout << "Error: Usage is " << std::endl;
          std::cout << "  " << argv[0] << " [ -i www.xxx.yy.zz -v 1 -p 9090]"
                    << std::endl;
          return -1;
          break;
      }
    }
  }
  std::cout << "Command line options: -i " << smf_ip_address.c_str() << ", -v "
            << std::to_string(http_version) << ", -p " << port.c_str()
            << std::endl;

  bool cont = false;
  uint8_t context_id = 1;
  uint8_t pid = 1;

  test_all_procedures_for_one_session(pid, context_id, smf_ip_address,
                                      http_version, port);
  //test_session_establishment_multiple_threads(smf_ip_address, http_version, port);
  //test_all_procedures_for_multiple_threads(smf_ip_address, http_version,
  //                                         port);
  return 0;
}

