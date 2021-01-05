/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 *file except in compliance with the License. You may obtain a copy of the
 *License at
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

/*! \file smf_profile.cpp
 \brief
 \author  Tien-Thinh NGUYEN
 \company Eurecom
 \date 2020
 \email: Tien-Thinh.Nguyen@eurecom.fr
 */

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include "logger.hpp"
#include "smf_profile.hpp"
#include "string.hpp"

using namespace std;
using namespace smf;

//------------------------------------------------------------------------------
void smf_profile::set_nf_instance_id(const std::string &instance_id) {
  nf_instance_id = instance_id;
}

//------------------------------------------------------------------------------
void smf_profile::get_nf_instance_id(std::string &instance_id) const {
  instance_id = nf_instance_id;
}

//------------------------------------------------------------------------------
std::string smf_profile::get_nf_instance_id() const { return nf_instance_id; }

//------------------------------------------------------------------------------
void smf_profile::set_nf_instance_name(const std::string &instance_name) {
  nf_instance_name = instance_name;
}

//------------------------------------------------------------------------------
void smf_profile::get_nf_instance_name(std::string &instance_name) const {
  instance_name = nf_instance_name;
}

//------------------------------------------------------------------------------
std::string smf_profile::get_nf_instance_name() const {
  return nf_instance_name;
}

//------------------------------------------------------------------------------
void smf_profile::set_nf_type(const std::string &type) { nf_type = type; }

//------------------------------------------------------------------------------
std::string smf_profile::get_nf_type() const { return nf_type; }
//------------------------------------------------------------------------------
void smf_profile::set_nf_status(const std::string &status) {
  nf_status = status;
}

//------------------------------------------------------------------------------
void smf_profile::get_nf_status(std::string &status) const {
  status = nf_status;
}

//------------------------------------------------------------------------------
std::string smf_profile::get_nf_status() const { return nf_status; }

//------------------------------------------------------------------------------
void smf_profile::set_nf_heartBeat_timer(const int32_t &timer) {
  heartBeat_timer = timer;
}

//------------------------------------------------------------------------------
void smf_profile::get_nf_heartBeat_timer(int32_t &timer) const {
  timer = heartBeat_timer;
}

//------------------------------------------------------------------------------
int32_t smf_profile::get_nf_heartBeat_timer() const { return heartBeat_timer; }

//------------------------------------------------------------------------------
void smf_profile::set_nf_priority(const uint16_t &p) { priority = p; }

//------------------------------------------------------------------------------
void smf_profile::get_nf_priority(uint16_t &p) const { p = priority; }

//------------------------------------------------------------------------------
uint16_t smf_profile::get_nf_priority() const { return priority; }

//------------------------------------------------------------------------------
void smf_profile::set_nf_capacity(const uint16_t &c) { capacity = c; }

//------------------------------------------------------------------------------
void smf_profile::get_nf_capacity(uint16_t &c) const { c = capacity; }

//------------------------------------------------------------------------------
uint16_t smf_profile::get_nf_capacity() const { return capacity; }

//------------------------------------------------------------------------------
void smf_profile::set_nf_snssais(const std::vector<snssai_t> &s) {
  snssais = s;
}

//------------------------------------------------------------------------------
void smf_profile::get_nf_snssais(std::vector<snssai_t> &s) const {
  s = snssais;
}

//------------------------------------------------------------------------------
void smf_profile::add_snssai(const snssai_t &s) { snssais.push_back(s); }
//------------------------------------------------------------------------------
void smf_profile::set_nf_ipv4_addresses(const std::vector<struct in_addr> &a) {
  ipv4_addresses = a;
}

//------------------------------------------------------------------------------
void smf_profile::add_nf_ipv4_addresses(const struct in_addr &a) {
  ipv4_addresses.push_back(a);
}
//------------------------------------------------------------------------------
void smf_profile::get_nf_ipv4_addresses(std::vector<struct in_addr> &a) const {
  a = ipv4_addresses;
}

//------------------------------------------------------------------------------
void smf_profile::set_custom_info(const nlohmann::json &c) { custom_info = c; }

//------------------------------------------------------------------------------
void smf_profile::get_custom_info(nlohmann::json &c) const { c = custom_info; }

//------------------------------------------------------------------------------
void smf_profile::display() {
  Logger::smf_app().debug("NF instance info");

  Logger::smf_app().debug("\tInstance ID: %s", nf_instance_id.c_str());

  Logger::smf_app().debug("\tInstance name: %s", nf_instance_name.c_str());
  Logger::smf_app().debug("\tInstance type: %s", nf_type.c_str());
  Logger::smf_app().debug("\tStatus: %s", nf_status.c_str());
  Logger::smf_app().debug("\tHeartBeat timer: %d", heartBeat_timer);
  Logger::smf_app().debug("\tPriority: %d", priority);
  Logger::smf_app().debug("\tCapacity: %d", capacity);
  // SNSSAIs
  for (auto s : snssais) {
    Logger::smf_app().debug("\tNNSSAI(SST, SD): %d, %s", s.sST, s.sD.c_str());
  }

  // IPv4 Addresses
  for (auto address : ipv4_addresses) {
    Logger::smf_app().debug("\tIPv4 Addr: %s", inet_ntoa(address));
  }

  if (!custom_info.empty()) {
    Logger::smf_app().debug("\tCustom info: %s", custom_info.dump().c_str());
  }
}

//------------------------------------------------------------------------------
void smf_profile::to_json(nlohmann::json &data) const {
  data["nfInstanceId"] = nf_instance_id;
  data["nfInstanceName"] = nf_instance_name;
  data["nfType"] = nf_type;
  data["nfStatus"] = nf_status;
  data["heartBeatTimer"] = heartBeat_timer;
  // SNSSAIs
  data["sNssais"] = nlohmann::json::array();
  for (auto s : snssais) {
    nlohmann::json tmp = {};
    tmp["sst"] = s.sST;
    tmp["sd"] = s.sD;
    ;
    data["sNssais"].push_back(tmp);
  }
  // ipv4_addresses
  data["ipv4Addresses"] = nlohmann::json::array();
  for (auto address : ipv4_addresses) {
    nlohmann::json tmp = inet_ntoa(address);
    data["ipv4Addresses"].push_back(tmp);
  }

  data["priority"] = priority;
  data["capacity"] = capacity;
  data["custom_info"] = custom_info;
}

//------------------------------------------------------------------------------
void smf_profile::handle_heartbeart_timeout(uint64_t ms) {
  Logger::smf_app().info("Handle heartbeart timeout profile %s, time %d",
                         nf_instance_id.c_str(), ms);
  set_nf_status("SUSPENDED");
}
