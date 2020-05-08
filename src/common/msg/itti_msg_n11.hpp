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

/*
 *  itti_msg_n11.hpp
 *
 *  Created on:
 *  Author:
 */

#ifndef ITTI_MSG_N11_HPP_INCLUDED_
#define ITTI_MSG_N11_HPP_INCLUDED_

#include "itti_msg.hpp"
#include "smf_msg.hpp"
#include "pistache/http.h"

class itti_n11_msg : public itti_msg {
 public:
  itti_n11_msg(const itti_msg_type_t msg_type, const task_id_t orig,
               const task_id_t dest)
      :
      itti_msg(msg_type, orig, dest) {

  }
  itti_n11_msg(const itti_n11_msg &i)
      :
      itti_msg(i) {
  }
  itti_n11_msg(const itti_n11_msg &i, const task_id_t orig,
               const task_id_t dest)
      :
      itti_n11_msg(i) {
    origin = orig;
    destination = dest;
  }

};

//-----------------------------------------------------------------------------
class itti_n11_create_sm_context_request : public itti_n11_msg {
 public:
  itti_n11_create_sm_context_request(const task_id_t orig, const task_id_t dest,
                                     Pistache::Http::ResponseWriter &response)
      :
      itti_n11_msg(N11_SESSION_CREATE_SM_CONTEXT_REQUEST, orig, dest),
      http_response(response),
      req(),
      scid() {
  }
  itti_n11_create_sm_context_request(
      const itti_n11_create_sm_context_request &i)
      :
      itti_n11_msg(i),
      req(i.req),
      http_response(i.http_response),
      scid() {
  }
  itti_n11_create_sm_context_request(
      const itti_n11_create_sm_context_request &i, const task_id_t orig,
      const task_id_t dest)
      :
      itti_n11_msg(i, orig, dest),
      req(i.req),
      http_response(i.http_response),
      scid(i.scid) {
  }
  const char* get_msg_name() {
    return "N11_SESSION_CREATE_SM_CONTEXT_REQUEST";
  }
  ;
  void set_scid(scid_t id) {
    scid = id;
  }
  ;
  smf::pdu_session_create_sm_context_request req;
  Pistache::Http::ResponseWriter &http_response;
  scid_t scid;  //SM Context ID

};

//-----------------------------------------------------------------------------
class itti_n11_create_sm_context_response : public itti_n11_msg {
 public:
  itti_n11_create_sm_context_response(const task_id_t orig,
                                      const task_id_t dest,
                                      Pistache::Http::ResponseWriter &response)
      :
      itti_n11_msg(N11_SESSION_CREATE_SM_CONTEXT_RESPONSE, orig, dest),
      http_response(response.clone()),
      scid(0) {
  }
  itti_n11_create_sm_context_response(
      const itti_n11_create_sm_context_response &i)
      :
      itti_n11_msg(i),
      res(i.res),
      http_response(i.http_response.clone()),
      scid(i.scid) {
  }
  itti_n11_create_sm_context_response(
      const itti_n11_create_sm_context_response &i, const task_id_t orig,
      const task_id_t dest)
      :
      itti_n11_msg(i, orig, dest),
      res(i.res),
      http_response(i.http_response.clone()),
      scid(i.scid) {
  }
  const char* get_msg_name() {
    return "N11_SESSION_CREATE_SM_CONTEXT_RESPONSE";
  }
  ;
  smf::pdu_session_create_sm_context_response res;
  Pistache::Http::ResponseWriter http_response;
  void set_scid(scid_t id) {
    scid = id;
  }
  ;
  scid_t scid;  //SM Context ID

};

//-----------------------------------------------------------------------------
class itti_n11_update_sm_context_request : public itti_n11_msg {
 public:
  itti_n11_update_sm_context_request(const task_id_t orig, const task_id_t dest,
                                     Pistache::Http::ResponseWriter &response)
      :
      itti_n11_msg(N11_SESSION_UPDATE_SM_CONTEXT_REQUEST, orig, dest),
      http_response(response) {
  }
  itti_n11_update_sm_context_request(const task_id_t orig, const task_id_t dest,
                                     Pistache::Http::ResponseWriter &response,
                                     const std::string id)
      :
      itti_n11_msg(N11_SESSION_UPDATE_SM_CONTEXT_REQUEST, orig, dest),
      http_response(response),
      scid(id) {
  }
  itti_n11_update_sm_context_request(
      const itti_n11_update_sm_context_request &i)
      :
      itti_n11_msg(i),
      req(i.req),
      http_response(i.http_response),
      scid(i.scid) {
  }
  itti_n11_update_sm_context_request(
      const itti_n11_update_sm_context_request &i, const task_id_t orig,
      const task_id_t dest)
      :
      itti_n11_msg(i, orig, dest),
      req(i.req),
      http_response(i.http_response),
      scid(i.scid) {
  }
  const char* get_msg_name() {
    return "N11_SESSION_UPDATE_SM_CONTEXT_REQUEST";
  }
  ;
  smf::pdu_session_update_sm_context_request req;
  Pistache::Http::ResponseWriter &http_response;
  std::string scid;  //SM Context ID
};

//-----------------------------------------------------------------------------
class itti_n11_update_sm_context_response : public itti_n11_msg {
 public:
  itti_n11_update_sm_context_response(const task_id_t orig,
                                      const task_id_t dest,
                                      Pistache::Http::ResponseWriter &response)
      :
      itti_n11_msg(N11_SESSION_UPDATE_SM_CONTEXT_RESPONSE, orig, dest),
      http_response(response.clone()),
      res(),
      session_procedure_type() {
  }
  itti_n11_update_sm_context_response(
      const itti_n11_update_sm_context_response &i)
      :
      itti_n11_msg(i),
      res(i.res),
      http_response(i.http_response.clone()),
      session_procedure_type(i.session_procedure_type) {
  }
  itti_n11_update_sm_context_response(
      const itti_n11_update_sm_context_response &i, const task_id_t orig,
      const task_id_t dest)
      :
      itti_n11_msg(i, orig, dest),
      res(i.res),
      http_response(i.http_response.clone()),
      session_procedure_type(i.session_procedure_type) {
  }
  const char* get_msg_name() {
    return "N11_SESSION_UPDATE_SM_CONTEXT_RESPONSE";
  }
  ;
  smf::pdu_session_update_sm_context_response res;
  Pistache::Http::ResponseWriter http_response;
  session_management_procedures_type_e session_procedure_type;

};

//-----------------------------------------------------------------------------
class itti_n11_modify_session_request_smf_requested : public itti_n11_msg {
 public:
  itti_n11_modify_session_request_smf_requested(const task_id_t orig,
                                                const task_id_t dest)
      :
      itti_n11_msg(N11_SESSION_MODIFICATION_REQUEST_SMF_REQUESTED, orig, dest) {
  }
  itti_n11_modify_session_request_smf_requested(
      const itti_n11_modify_session_request_smf_requested &i)
      :
      itti_n11_msg(i),
      req(i.req) {
  }
  itti_n11_modify_session_request_smf_requested(
      const itti_n11_modify_session_request_smf_requested &i,
      const task_id_t orig, const task_id_t dest)
      :
      itti_n11_msg(i, orig, dest),
      req(i.req) {
  }
  const char* get_msg_name() {
    return "N11_SESSION_MODIFICATION_REQUEST_SMF_REQUESTED";
  }
  ;
  smf::pdu_session_create_sm_context_request req;
};

//-----------------------------------------------------------------------------
class itti_n11_update_pdu_session_status : public itti_n11_msg {
 public:
  itti_n11_update_pdu_session_status(const task_id_t orig, const task_id_t dest)
      :
      itti_n11_msg(N11_SESSION_UPDATE_PDU_SESSION_STATUS, orig, dest),
      scid(0),
      pdu_session_status(pdu_session_status_e::PDU_SESSION_INACTIVE) {
  }
  itti_n11_update_pdu_session_status(
      const itti_n11_update_pdu_session_status &i)
      :
      itti_n11_msg(i),
      scid(i.scid),
      pdu_session_status(i.pdu_session_status) {
  }
  itti_n11_update_pdu_session_status(
      const itti_n11_update_pdu_session_status &i, const task_id_t orig,
      const task_id_t dest)
      :
      itti_n11_msg(i, orig, dest),
      scid(i.scid),
      pdu_session_status(i.pdu_session_status) {
  }
  const char* get_msg_name() {
    return "N11_SESSION_UPDATE_PDU_SESSION_STATUS";
  }
  ;
  void set_scid(scid_t id) {
    scid = id;
  }
  ;
  scid_t scid;  //SM Context ID
  pdu_session_status_e pdu_session_status;
  void set_pdu_session_status(pdu_session_status_e status) {
    pdu_session_status = status;
  }
  ;

};

//-----------------------------------------------------------------------------
class itti_n11_n1n2_message_transfer_response_status : public itti_n11_msg {
 public:
  itti_n11_n1n2_message_transfer_response_status(const task_id_t orig,
                                                 const task_id_t dest)
      :
      itti_n11_msg(N11_SESSION_N1N2_MESSAGE_TRANSFER_RESPONSE_STATUS, orig,
                   dest),
      scid(0),
      response_code(0),
      msg_type(0) {
  }
  itti_n11_n1n2_message_transfer_response_status(
      const itti_n11_n1n2_message_transfer_response_status &i)
      :
      itti_n11_msg(i),
      scid(i.scid),
      response_code(i.response_code),
      msg_type(i.msg_type) {
  }
  itti_n11_n1n2_message_transfer_response_status(
      const itti_n11_n1n2_message_transfer_response_status &i,
      const task_id_t orig, const task_id_t dest)
      :
      itti_n11_msg(i, orig, dest),
      scid(i.scid),
      response_code(i.response_code),
      msg_type(i.msg_type) {
  }
  const char* get_msg_name() {
    return "N11_SESSION_N1N2_MESSAGE_TRANSFER_RESPONSE_STATUS";
  }
  ;
  void set_scid(scid_t id) {
    scid = id;
  }
  ;
  void set_response_code(int16_t code) {
    response_code = code;
  }
  ;
  void set_cause(std::string c) {
    cause = c;
  }
  ;
  void set_msg_type(uint8_t type) {
    msg_type = type;
  }
  ;
  scid_t scid;  //SM Context ID
  int16_t response_code;
  std::string cause;
  uint8_t msg_type;

};

//-----------------------------------------------------------------------------
class itti_n11_release_sm_context_request : public itti_n11_msg {
 public:
  itti_n11_release_sm_context_request(const task_id_t orig,
                                      const task_id_t dest,
                                      Pistache::Http::ResponseWriter &response)
      :
      itti_n11_msg(N11_SESSION_RELEASE_SM_CONTEXT_REQUEST, orig, dest),
      http_response(response) {
  }
  itti_n11_release_sm_context_request(const task_id_t orig,
                                      const task_id_t dest,
                                      Pistache::Http::ResponseWriter &response,
                                      const std::string id)
      :
      itti_n11_msg(N11_SESSION_RELEASE_SM_CONTEXT_REQUEST, orig, dest),
      http_response(response),
      scid(id) {
  }
  itti_n11_release_sm_context_request(
      const itti_n11_release_sm_context_request &i)
      :
      itti_n11_msg(i),
      http_response(i.http_response),
      scid(i.scid),
      req(i.req) {
  }
  itti_n11_release_sm_context_request(
      const itti_n11_release_sm_context_request &i, const task_id_t orig,
      const task_id_t dest)
      :
      itti_n11_msg(i, orig, dest),
      http_response(i.http_response),
      scid(i.scid),
      req(i.req) {
  }
  const char* get_msg_name() {
    return "N11_SESSION_RELEASE_SM_CONTEXT_REQUEST";
  }
  ;
  smf::pdu_session_release_sm_context_request req;
  Pistache::Http::ResponseWriter &http_response;
  std::string scid;  //SM Context ID

};

//-----------------------------------------------------------------------------
class itti_n11_release_sm_context_response : public itti_n11_msg {
 public:
  itti_n11_release_sm_context_response(const task_id_t orig,
                                      const task_id_t dest,
                                      Pistache::Http::ResponseWriter &response)
      :
      itti_n11_msg(N11_SESSION_RELEASE_SM_CONTEXT_RESPONSE, orig, dest),
      http_response(response.clone()),
      res() {
  }
  itti_n11_release_sm_context_response(
      const itti_n11_release_sm_context_response &i)
      :
      itti_n11_msg(i),
      res(i.res),
      http_response(i.http_response.clone()) {
  }
  itti_n11_release_sm_context_response(
      const itti_n11_release_sm_context_response &i, const task_id_t orig,
      const task_id_t dest)
      :
      itti_n11_msg(i, orig, dest),
      res(i.res),
      http_response(i.http_response.clone()) {
  }
  const char* get_msg_name() {
    return "N11_SESSION_RELEASE_SM_CONTEXT_RESPONSE";
  }
  ;
  smf::pdu_session_release_sm_context_response res;
  Pistache::Http::ResponseWriter http_response;

};


#endif /* ITTI_MSG_N11_HPP_INCLUDED_ */
