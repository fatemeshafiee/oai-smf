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

/*! \file smf_n11.hpp
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#ifndef FILE_SMF_N11_HPP_SEEN
#define FILE_SMF_N11_HPP_SEEN

#include <thread>
#include <map>

#include "smf.h"
#include <curl/curl.h>
#include "3gpp_29.503.h"
#include "smf_context.hpp"
#include "SmContextCreatedData.h"
#include "SmContextUpdatedData.h"
#include "SmContextUpdateError.h"

namespace smf {

class smf_n11 {
 private:
  std::thread::id thread_id;
  std::thread thread;

 public:
  smf_n11();
  smf_n11(smf_n11 const&) = delete;
  void operator=(smf_n11 const&) = delete;

  /*
   * Send N1N2 Message Transfer Request to AMF
   * @param [std::shared_ptr<itti_n11_create_sm_context_response>] sm_context_res: Content of message to be sent
   * @return void
   */
  void send_n1n2_message_transfer_request(
      std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res);

  /*
   * Send N1N2 Message Transfer Request to AMF
   * @param [std::shared_ptr<itti_nx_trigger_pdu_session_modification>] sm_session_modification: Content of message to be sent
   * @return void
   */
  void send_n1n2_message_transfer_request(
      std::shared_ptr<itti_nx_trigger_pdu_session_modification> sm_session_modification);

  /*
   * Send N1N2 Message Transfer Request to AMF
   * @param [std::shared_ptr<itti_n11_session_report_request>] n11_msg: Content of message to be sent
   * @return void
   */
  void send_n1n2_message_transfer_request(
      std::shared_ptr<itti_n11_session_report_request> report_msg);

  /*
   * Send SM Context Status Notification to AMF
   * @param [std::shared_ptr<itti_n11_notify_sm_context_status>] sm_context_status: Content of message to be sent
   * @return void
   */
  void send_sm_context_status_notification(
      std::shared_ptr<itti_n11_notify_sm_context_status> sm_context_status);

  /*
   * Send Notification for the associated event to the subscribers
   * @param [std::shared_ptr<itti_n11_notify_subscribed_event>] msg: Content of message to be sent
   * @return void
   */
  void notify_subscribed_event(
      std::shared_ptr<itti_n11_notify_subscribed_event> msg);

  /*
   * Create Curl handle for multi curl
   * @param [event_notification&] ev_notif: content of the event notification
   * @param [std::string *] data: data
   * @return pointer to the created curl
   */
  CURL * curl_create_handle (event_notification &ev_notif, std::string *data);

};
}
#endif /* FILE_SMF_N11_HPP_SEEN */
