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

/*! \file smf_event.hpp
 \brief
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: tien-thinh.nguyen@eurecom.fr
 */

#ifndef FILE_SMF_EVENT_HPP_SEEN
#define FILE_SMF_EVENT_HPP_SEEN

#include <boost/signals2.hpp>

#include "smf.h"

namespace smf {

typedef boost::signals2::signal<void(scid_t, uint32_t, uint8_t)> sm_context_status_sig_t;

class smf_event {

 public:
  smf_event();
  smf_event(smf_event const&) = delete;
  void operator=(smf_event const&) = delete;

  /*
   * Subscribe to SM Context Status Notification signal
   * @param [const sm_context_status_sig_t::slot_type&] context_status_st:  slot_type parameter
   * @return boost::signals2::connection: the connection between the signal and the slot
   */
  boost::signals2::connection subscribe_sm_context_status_notification(const sm_context_status_sig_t::slot_type& context_status_st);

  /*
   * Send SM Context Status Notification to AMF
   * @param [scid_t] scid: SMF Context ID
   * @param [uint32_t] status: Updated status
   * @param [uint8_t] http_version: HTTP version
   * @return void
   */
  void trigger_sm_context_status_notification(scid_t scid, uint32_t status, uint8_t http_version);

 private:
  sm_context_status_sig_t sm_context_status_sig;

};
}
#endif /* FILE_SMF_EVENT_HPP_SEEN */
