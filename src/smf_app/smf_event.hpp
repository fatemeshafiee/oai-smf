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
#include "3gpp_24.007.h"

namespace smf {

typedef boost::signals2::signal<void(scid_t, uint8_t, uint8_t)> sm_context_status_sig_t; //SCID, PDU Session Status, HTTP version
//For Event Exposure
typedef boost::signals2::signal<void(supi64_t, pdu_session_id_t, uint8_t)> ee_pdu_session_release_sig_t; //SUPI, PDU SessionID, HTTP version
//typedef boost::signals2::signal<void(uint32_t, uint32_t)> ee_ue_ip_address_change_sig_t; //UI IP Address, UE ID
//TODO:
//Access Type Change
//UP Path Change
//PLMN Change
//Downlink data delivery status

class smf_event {

 public:
  smf_event();
  smf_event(smf_event const&) = delete;
  void operator=(smf_event const&) = delete;

  static smf_event& get_instance() {
    static smf_event instance;
    return instance;
  }


  /*
   * Bind the signals to corresponding slot for each event
   * @return void
   */
  void bind();

  /*
   * Subscribe to SM Context Status Notification signal
   * @param [const sm_context_status_sig_t::slot_type&] context_status_st:  slot_type parameter
   * @return boost::signals2::connection: the connection between the signal and the slot
   */
  boost::signals2::connection subscribe_sm_context_status_notification(const sm_context_status_sig_t::slot_type& context_status_st);

  /*
   * Subscribe to Event Exposure Event: PDU Session Release
   * @param [const ee_pdu_session_release_sig_t::slot_type&] pdu_session_release_st:  slot_type parameter
   * @return boost::signals2::connection: the connection between the signal and the slot
   */
  boost::signals2::connection subscribe_ee_pdu_session_release(const ee_pdu_session_release_sig_t::slot_type& pdu_session_release_st);

  /*
   * Trigger the signal to send SM Context Status Notification to AMF
   * @param [scid_t] scid: SMF Context ID
   * @param [uint8_t] status: Updated status
   * @param [uint8_t] http_version: HTTP version
   * @return void
   */
  void trigger_sm_context_status_notification(scid_t scid, uint8_t status, uint8_t http_version);

  /*
   * Send SM Context Status Notification to AMF
   * @param [scid_t] scid: SMF Context ID
   * @param [uint8_t] status: Updated status
   * @param [uint8_t] http_version: HTTP version
   * @return void
   */
  void send_sm_context_status_notification(scid_t scid, uint8_t status, uint8_t http_version) ;

  /*
   * Trigger the signal to send PDU Session Release notification to subscribed NFs
   * @param [supi64_t] supi: UE SUPI
   * @param [pdu_session_id_t] pdu_session_id: PDU Session ID
   * @param [uint8_t] http_version: HTTP version
   * @return void
   */
  void trigger_ee_pdu_session_release(supi64_t supi, pdu_session_id_t pdu_session_id, uint8_t http_version);

  /*
   * Send PDU Session Release notification to subscribed NFs
   * @param [supi64_t] supi: UE SUPI
   * @param [pdu_session_id_t] pdu_session_id: PDU Session ID
   * @param [uint8_t] http_version: HTTP version
   * @return void
   */
  void send_ee_pdu_session_release(supi64_t supi, pdu_session_id_t pdu_session_id, uint8_t http_version) ;

 private:
  sm_context_status_sig_t sm_context_status_sig; //Signal for SM Context status update
  ee_pdu_session_release_sig_t pdu_session_release_sig; //Signal for PDU session release event
  bool pdu_session_release_sig_is_connected;

};
}
#endif /* FILE_SMF_EVENT_HPP_SEEN */
