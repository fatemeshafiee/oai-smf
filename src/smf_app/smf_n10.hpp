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
   \author  
   \date 2019
   \email: 
*/

#ifndef FILE_SMF_N10_HPP_SEEN
#define FILE_SMF_N10_HPP_SEEN

#include "smf.h"
#include "3gpp_29.503.h"
#include "smf_context.hpp"
#include <thread>
#include <map>

namespace smf {

class smf_n10 {
private:
  std::thread::id                      thread_id;
  std::thread                          thread;

  void handle_receive_sm_data_notification();

public:
  smf_n10();
  smf_n10(smf_n10 const&)    = delete;
  void operator=(smf_n10 const&)     = delete;
  bool get_sm_data(supi64_t& supi, std::string& dnn, snssai_t& snssai, std::shared_ptr<session_management_subscription> subscription);
  void subscribe_sm_data();

};


}
#endif /* FILE_SMF_N10_HPP_SEEN */
