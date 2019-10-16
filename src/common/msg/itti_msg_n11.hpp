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
	itti_n11_msg(const itti_msg_type_t  msg_type, const task_id_t orig, const task_id_t dest):
    itti_msg(msg_type, orig, dest) {

  }
	itti_n11_msg(const itti_n11_msg& i) : itti_msg(i) {}
	itti_n11_msg(const itti_n11_msg& i, const task_id_t orig, const task_id_t dest) :
		itti_n11_msg(i)
  {
    origin = orig;
    destination = dest;
  }

};

//-----------------------------------------------------------------------------
class itti_n11_create_sm_context_request : public itti_n11_msg {
public:
	itti_n11_create_sm_context_request(const task_id_t orig, const task_id_t dest, Pistache::Http::ResponseWriter& response):
		itti_n11_msg(N11_SESSION_CREATE_SM_CONTEXT_REQUEST, orig, dest), http_response(response) {}
	itti_n11_create_sm_context_request(const itti_n11_create_sm_context_request& i) : itti_n11_msg(i), req(i.req), http_response(i.http_response)  {}
  itti_n11_create_sm_context_request(const itti_n11_create_sm_context_request& i, const task_id_t orig, const task_id_t dest) :
	  itti_n11_msg(i, orig, dest), req(i.req), http_response(i.http_response) {}
  const char* get_msg_name() {return "N11_SESSION_CREATE_SM_CONTEXT_REQUEST";};
  smf::pdu_session_create_sm_context_request req;
  Pistache::Http::ResponseWriter& http_response;


};


//-----------------------------------------------------------------------------
class itti_n11_create_sm_context_response : public itti_n11_msg {
public:
	itti_n11_create_sm_context_response(const task_id_t orig, const task_id_t dest, Pistache::Http::ResponseWriter& response):
		itti_n11_msg(N11_SESSION_CREATE_SM_CONTEXT_RESPONSE, orig, dest),  http_response(response.clone()) {}
	itti_n11_create_sm_context_response(const itti_n11_create_sm_context_response& i) : itti_n11_msg(i), res(i.res), http_response(i.http_response.clone())  {}
	itti_n11_create_sm_context_response(const itti_n11_create_sm_context_response& i, const task_id_t orig, const task_id_t dest) :
	  itti_n11_msg(i, orig, dest), res(i.res), http_response(i.http_response.clone()) {}
  const char* get_msg_name() {return "N11_SESSION_CREATE_SM_CONTEXT_RESPONSE";};
  smf::pdu_session_create_sm_context_response res;
  Pistache::Http::ResponseWriter http_response;

};


#endif /* ITTI_MSG_N11_HPP_INCLUDED_ */
