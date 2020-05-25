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

/*! \file smf_n10.hpp
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2019
 \email: tien-thinh.nguyen@eurecom.fr
 */

#ifndef FILE_SMF_N10_HPP_SEEN
#define FILE_SMF_N10_HPP_SEEN

#include <thread>
#include <map>

#include "smf.h"
#include "3gpp_29.503.h"
#include "smf_context.hpp"

namespace smf {

class smf_n10 {
 private:
  std::thread::id thread_id;
  std::thread thread;

 public:
  smf_n10();
  smf_n10(smf_n10 const&) = delete;
  void operator=(smf_n10 const&) = delete;

  /*
   * Get SM subscription data from UDM
   * @param [const supi64_t &] supi
   * @param [const std::string &] dnn
   * @param [const snssai_t &] snssai
   * @param [std::shared_ptr<session_management_subscription>] subscription
   * @return bool: True if successful, otherwise false
   *
   */
  bool get_sm_data(
      const supi64_t &supi, const std::string &dnn, const snssai_t &snssai,
      std::shared_ptr<session_management_subscription> subscription);

  /*
   * Subscribe to be notify from UDM
   * @param []
   * @return void
   *
   */
  void subscribe_sm_data();

};

}
#endif /* FILE_SMF_N10_HPP_SEEN */
