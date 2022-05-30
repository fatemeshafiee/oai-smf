/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
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

/*! \file smf_n7.hpp
 \author  Stefan Spettel
 \company Openairinterface Software Alliance
 \date 2021
 \email: stefan.spettel@gmx.at
 */

#ifndef FILE_SMF_N7_HPP_SEEN
#define FILE_SMF_N7_HPP_SEEN

#include <string>
#include "Snssai.h"
#include "PlmnId.h"

namespace smf::n7 {

class smf_n7 {
 public:
  explicit smf_n7();

  virtual ~smf_n7();

  bool discover_pcf(
      std::string& addr, std::string& port, std::string& api_version,
      const oai::smf_server::model::Snssai snssai,
      const oai::smf_server::model::PlmnId, const std::string);

 private:
  bool discover_pcf_with_nrf(
      std::string& addr, std::string& port, std::string& api_version,
      const oai::smf_server::model::Snssai snssai,
      const oai::smf_server::model::PlmnId, const std::string);

  bool discover_pcf_from_config_file(
      std::string& addr, std::string& port, std::string& api_version,
      const oai::smf_server::model::Snssai snssai,
      const oai::smf_server::model::PlmnId, const std::string);
};
}  // namespace smf::n7
#endif /* FILE_SMF_N4_HPP_SEEN */
