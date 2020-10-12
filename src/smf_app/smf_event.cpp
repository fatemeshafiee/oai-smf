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

/*! \file smf_event.cpp
 \brief
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: tien-thinh.nguyen@eurecom.fr
 */

#include "smf_event.hpp"

using namespace smf;

extern smf_event *smf_event_inst;

//------------------------------------------------------------------------------
smf_event::smf_event() {
}

//------------------------------------------------------------------------------
boost::signals2::connection smf_event::subscribe_sm_context_status_notification(const sm_context_status_sig_t::slot_type& context_status_st) {
  return sm_context_status_sig.connect(context_status_st);
}

//------------------------------------------------------------------------------
void smf_event::trigger_sm_context_status_notification(scid_t scid, uint32_t status, uint8_t http_version) {
  sm_context_status_sig(scid, status, http_version);
}


