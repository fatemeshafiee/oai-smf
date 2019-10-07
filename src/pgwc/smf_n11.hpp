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
   \author  
   \date 2019
   \email: 
 */

#ifndef FILE_SMF_N11_HPP_SEEN
#define FILE_SMF_N11_HPP_SEEN

#include "smf.h"
#include "3gpp_29.503.h"
#include "pgw_context.hpp"
#include <thread>
#include <map>

namespace pgwc {

class smf_n11 {
private:
	std::thread::id thread_id;
	std::thread thread;

	void handle_receive_sm_data_notification();

	std::string amf_addr;
	int amf_port;

public:
	smf_n11();
	smf_n11(smf_n11 const&)    = delete;
	void operator=(smf_n11 const&)     = delete;
	void send_msg_to_amf(std::shared_ptr<itti_n11_create_sm_context_response> sm_context_res);

};


}
#endif /* FILE_SMF_N11_HPP_SEEN */
