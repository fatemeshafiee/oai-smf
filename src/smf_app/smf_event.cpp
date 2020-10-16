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
#include "smf_subscription.hpp"
#include "smf_app.hpp"
#include "itti.hpp"

using namespace smf;

extern smf_event *smf_event_inst;
extern smf::smf_app *smf_app_inst;
extern itti_mw *itti_inst;

smf_event::smf_event() {
 //bind signal to slot type	
 bind();
}
//------------------------------------------------------------------------------
void smf_event::bind() {
  //by default, subscribe to the events
  subscribe_sm_context_status_notification(
      boost::bind(&smf_event::send_sm_context_status_notification, this, _1, _1,
                  _1));
  subscribe_ee_pdu_session_release(
      boost::bind(&smf_event::send_ee_pdu_session_release, this, _1, _1, _1));
}

//------------------------------------------------------------------------------
boost::signals2::connection smf_event::subscribe_sm_context_status_notification(
    const sm_context_status_sig_t::slot_type &context_status_st) {
  return sm_context_status_sig.connect(context_status_st);
}

//------------------------------------------------------------------------------
void smf_event::trigger_sm_context_status_notification(scid_t scid,
                                                       uint8_t status,
                                                       uint8_t http_version) {
  sm_context_status_sig(scid, status, http_version);
}

//------------------------------------------------------------------------------
void smf_event::send_sm_context_status_notification(scid_t scid,
                                                    uint8_t status,
                                                    uint8_t http_version) {
  Logger::smf_app().debug("Send request to N11 to triger SM Context Status Notification, SMF Context ID " SCID_FMT " ", scid);
  std::shared_ptr<smf_context_ref> scf = { };

  if (smf_app_inst->is_scid_2_smf_context(scid)) {
    scf = smf_app_inst->scid_2_smf_context(scid);
  } else {
    Logger::smf_app().warn(
        "SM Context associated with this id " SCID_FMT " does not exit!", scid);
    //TODO:
    return;
  }

  //Send request to N11 to trigger the notification
  Logger::smf_app().debug(
      "Send ITTI msg to SMF N11 to trigger the status notification");
  std::shared_ptr<itti_n11_notify_sm_context_status> itti_msg = std::make_shared
      < itti_n11_notify_sm_context_status > (TASK_SMF_APP, TASK_SMF_N11);
  itti_msg->scid = scid;
  itti_msg->sm_context_status = sm_context_status_e2str[status];
  itti_msg->amf_status_uri = scf.get()->amf_status_uri;
  itti_msg->http_version = http_version;

  int ret = itti_inst->send_msg(itti_msg);
  if (RETURNok != ret) {
    Logger::smf_app().error(
        "Could not send ITTI message %s to task TASK_SMF_N11",
        itti_msg->get_msg_name());
  }
}

//------------------------------------------------------------------------------
boost::signals2::connection smf_event::subscribe_ee_pdu_session_release(
    const ee_pdu_session_release_sig_t::slot_type &pdu_session_release_st) {
  return pdu_session_release_sig.connect(pdu_session_release_st);
}

//------------------------------------------------------------------------------
void smf_event::trigger_ee_pdu_session_release(supi64_t supi,
                                               pdu_session_id_t pdu_session_id,
                                               uint8_t http_version) {
  pdu_session_release_sig(supi, pdu_session_id, http_version);
}

//------------------------------------------------------------------------------
void smf_event::send_ee_pdu_session_release(supi64_t supi,
                                            pdu_session_id_t pdu_session_id,
                                            uint8_t http_version) {
  Logger::smf_app().debug("Send request to N11 to triger PDU Session Release Notification, SUPI " SUPI_64_FMT " , PDU Session ID %d, HTTP version  %d", supi, pdu_session_id, http_version);

 //std::vector < std::shared_ptr < smf_subscription >> subscriptions;
  std::shared_ptr<smf_subscription> subscription = {};
  smf_app_inst->get_ee_subscriptions(smf_event_t::SMF_EVENT_PDU_SES_REL, supi,
                                     pdu_session_id, subscription);

  if (subscription.get() != nullptr) { 
    //Send request to N11 to trigger the notification to the subscribed event
    Logger::smf_app().debug(
      "Send ITTI msg to SMF N11 to trigger the event notification");
    std::shared_ptr<itti_n11_notify_subscribed_event> itti_msg = std::make_shared
      < itti_n11_notify_subscribed_event > (TASK_SMF_APP, TASK_SMF_N11);

    event_notification ev_notif = { };
    ev_notif.set_pdu_session_id(pdu_session_id);
    itti_msg->notif_id = std::to_string(subscription->sub_id);
    itti_msg->event_notifs.push_back(ev_notif);
    itti_msg->http_version = http_version;

    int ret = itti_inst->send_msg(itti_msg);
    if (RETURNok != ret) {
      Logger::smf_app().error(
        "Could not send ITTI message %s to task TASK_SMF_N11",
        itti_msg->get_msg_name());
    }
  }
}
