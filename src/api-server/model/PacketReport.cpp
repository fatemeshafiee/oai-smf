/**
 * Nsmf_EventExposure
 *
 * PacketReport.cpp
 */

/*
 * Added by: Fatemeh Shafiei Ardestani
 * Date: 2025-04-06
 * See Git history for complete list of changes.
 */

#include "PacketReport.h"
// #include <sstream>

namespace oai {
namespace smf_server {
namespace model {

PacketReport::PacketReport() {
  m_SEndID        = 0;
  m_SEndIDIsSet   = false;
  fatemeh_packet_type = 4;
  fatemeh_packet_typeIsSet = false;
  fatemeh_packet_data_length = 0;
  fatemeh_packet_data_data = "";
  fatemeh_packet_dataIsSet = false;
  fatemeh_packet_header_ip_version_and_header_length = 0;
  fatemeh_packet_header_tos = 0;
  fatemeh_packet_header_length = 0;
  fatemeh_packet_header_fragment_id = 0;
  fatemeh_packet_header_flags_and_fragment_offset = 0;
  fatemeh_packet_header_ttl = 0;
  fatemeh_packet_header_protocol = 0;
  fatemeh_packet_header_checksum = 0;
  fatemeh_packet_header_src = 0;
  fatemeh_packet_header_dst = 0;
  fatemeh_packet_headerIsSet = false;

  // m_urTrig        = {};
  // m_urTrigIsSet   = false;
}

PacketReport::~PacketReport() {}

void PacketReport::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const PacketReport& o) {
  j = nlohmann::json();
  if (o.SEndIDIsSet()) j["SEID"] = o.m_SEndID;
  if (o.packet_typeISset()) j["Packet Type"] = o.fatemeh_packet_type;
  // if (o.urTriggerIsSet()) {
  //   if (o.m_urTrig.perio) j["Trigger"] = "Periodic Reporting";
  //   if (o.m_urTrig.volth) j["Trigger"] = "Volume Threshold";
  //   if (o.m_urTrig.timth) j["Trigger"] = "Time Threshold";
  //   if (o.m_urTrig.volqu) j["Trigger"] = "Volume Quota";
  //   if (o.m_urTrig.timqu) j["Trigger"] = "Time Quota";

  // }
  if (o.lengthIsSet()) j["Packet Data"]["Data length"] = o.fatemeh_packet_data_length;
  if (o.dataIsSet()) j["Packet Data"]["Data"] = o.fatemeh_packet_data_data;
  if (o.ipvIsSet()) j["Packet Header"]["IP version and Header length"] = o.fatemeh_packet_header_ip_version_and_header_length;
  if (o.tosIsSet()) j["Packet Header"]["TOS"] = o.fatemeh_packet_header_tos;
  if (o.headerlengthIsSet()) j["Packet Header"]["Packet length"] = o.fatemeh_packet_header_length;
  if (o.frgIDIsSet()) j["Packet Header"]["Fragment ID"] = o.fatemeh_packet_header_fragment_id;
  if (o.flagsIsSet()) j["Packet Header"]["Flags and Fragment offset"] = o.fatemeh_packet_header_flags_and_fragment_offset;
  if (o.ttlIsSet()) j["Packet Header"]["TTL"] = o.fatemeh_packet_header_ttl;
  if (o.protocolIsSet()) j["Packet Header"]["Protocol"] = o.fatemeh_packet_header_protocol;
  if (o.checksumIsSet()) j["Packet Header"]["Checksum"] = o.fatemeh_packet_header_checksum;
  if (o.srcIsSet()) j["Packet Header"]["Source address"] = o.fatemeh_packet_header_src;
  if (o.dstIsSet()) j["Packet Header"]["Destination Address"] = o.fatemeh_packet_header_dst;
}

  // if (j.find("Trigger") != j.end()) {
  //   o.m_urTrigIsSet = true;
  //   auto s          = j.get<std::string>();
  //   s               = j.at("Trigger");
  //   if (s == "Periodic Reporting") o.m_urTrig.perio = 1;
  //   if (s == "Volume Threshold") o.m_urTrig.volth = 1;
  //   if (s == "Time Threshold") o.m_urTrig.timth = 1;
  //   if (s == "Volume Quota") o.m_urTrig.volqu = 1;
  //   if (s == "Time Quota")
  //     o.m_urTrig.timqu = 1;
  //   else {
  //     o.m_urTrigIsSet = false;
  //     // TODO: Handle invalid JSON
  //   }
void from_json(const nlohmann::json& j, PacketReport& o) {
    // SEID
    if (j.find("SEID") != j.end()) {
        j.at("SEID").get_to(o.m_SEndID);
        o.m_SEndIDIsSet = true;
    }

    // Packet Type
    if (j.find("Packet Type") != j.end()) {
        j.at("Packet Type").get_to(o.fatemeh_packet_type);
        o.fatemeh_packet_typeIsSet = true;
    }

    // Packet Data Length
    if (j["Packet Data"].find("Data length") != j["Packet Data"].end()) {
        j["Packet Data"]["Data length"].get_to(o.fatemeh_packet_data_length);
        o.fatemeh_packet_dataIsSet = true;
    }

    // Packet Data Data
    if (j["Packet Data"].find("Data") != j["Packet Data"].end()) {
        j["Packet Data"]["Data"].get_to(o.fatemeh_packet_data_data);
        o.fatemeh_packet_dataIsSet = true;
    }

    // IP Version and Header Length
    if (j["Packet Header"].find("IP version and Header length") != j["Packet Header"].end()) {
        j["Packet Header"]["IP version and Header length"].get_to(o.fatemeh_packet_header_ip_version_and_header_length);
        o.fatemeh_packet_headerIsSet = true;
    }

    // TOS
    if (j["Packet Header"].find("TOS") != j["Packet Header"].end()) {
        j["Packet Header"]["TOS"].get_to(o.fatemeh_packet_header_tos);
        o.fatemeh_packet_headerIsSet = true;
    }

    // Header Length
    if (j["Packet Header"].find("Packet length") != j["Packet Header"].end()) {
        j["Packet Header"]["Packet length"].get_to(o.fatemeh_packet_header_length);
        o.fatemeh_packet_headerIsSet = true;
    }

    // Fragment ID
    if (j["Packet Header"].find("Fragment ID") != j["Packet Header"].end()) {
        j["Packet Header"]["Fragment ID"].get_to(o.fatemeh_packet_header_fragment_id);
        o.fatemeh_packet_headerIsSet = true;
    }

    // Flags and Fragment Offset
    if (j["Packet Header"].find("Flags and Fragment offset") != j["Packet Header"].end()) {
        j["Packet Header"]["Flags and Fragment offset"].get_to(o.fatemeh_packet_header_flags_and_fragment_offset);
        o.fatemeh_packet_headerIsSet = true;
    }

    // TTL
    if (j["Packet Header"].find("TTL") != j["Packet Header"].end()) {
        j["Packet Header"]["TTL"].get_to(o.fatemeh_packet_header_ttl);
        o.fatemeh_packet_headerIsSet = true;
    }

    // Protocol
    if (j["Packet Header"].find("Protocol") != j["Packet Header"].end()) {
        j["Packet Header"]["Protocol"].get_to(o.fatemeh_packet_header_protocol);
        o.fatemeh_packet_headerIsSet = true;
    }

    // Checksum
    if (j["Packet Header"].find("Checksum") != j["Packet Header"].end()) {
        j["Packet Header"]["Checksum"].get_to(o.fatemeh_packet_header_checksum);
        o.fatemeh_packet_headerIsSet = true;
    }

    // Source Address
    if (j["Packet Header"].find("Source address") != j["Packet Header"].end()) {
        j["Packet Header"]["Source address"].get_to(o.fatemeh_packet_header_src);
        o.fatemeh_packet_headerIsSet = true;
    }

    // Destination Address
    if (j["Packet Header"].find("Destination Address") != j["Packet Header"].end()) {
        j["Packet Header"]["Destination Address"].get_to(o.fatemeh_packet_header_dst);
        o.fatemeh_packet_headerIsSet = true;
    }
}


int64_t PacketReport::getSEndID() const {
  return m_SEndID;
}
void PacketReport::setSEndID(int64_t const& value) {
  m_SEndID      = value;
  m_SEndIDIsSet = true;
}
bool PacketReport::SEndIDIsSet() const {
  return m_SEndIDIsSet;
}
void PacketReport::unsetSEndID() {
  m_SEndIDIsSet = false;
}

// fatemeh_packet_type
uint8_t PacketReport::getpacket_type() const {
  return fatemeh_packet_type;
}
void PacketReport::setpacket_type(uint8_t const& value) {
  fatemeh_packet_type = value;
  fatemeh_packet_typeIsSet = true;
}
bool PacketReport::packet_typeISset() const {
  return fatemeh_packet_typeIsSet;
}
void PacketReport::unsetpacket_type() {
  fatemeh_packet_typeIsSet = false;
}

// fatemeh_packet_data
uint16_t PacketReport::getdata_length() const {
  return fatemeh_packet_data_length;
}
void PacketReport::setdata_length(uint16_t const& value) {
  fatemeh_packet_data_length = value;
  fatemeh_packet_dataIsSet = true;
}
bool PacketReport::lengthIsSet() const {
  return fatemeh_packet_dataIsSet;
}
void PacketReport::unsetdata_length() {
  fatemeh_packet_dataIsSet = false;
}
 
std::string PacketReport::getdata_data() const {
  return fatemeh_packet_data_data;
}
void PacketReport::setdata_data(std::string const& value) {
  fatemeh_packet_data_data = value;
  fatemeh_packet_typeIsSet = true;
}
bool PacketReport::dataIsSet() const {
  return fatemeh_packet_dataIsSet;
}
void PacketReport::unsetdata_data() {
  fatemeh_packet_typeIsSet = false;
}

// fatemeh_packet_header
// 

uint8_t PacketReport::getipv() const {
  return fatemeh_packet_header_ip_version_and_header_length;
}
void PacketReport::setipv(uint8_t const& value) {
  fatemeh_packet_header_ip_version_and_header_length = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::ipvIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsetipv() {
  fatemeh_packet_headerIsSet = false;
}

uint8_t PacketReport::gettos() const {
  return fatemeh_packet_header_tos;
}
void PacketReport::settos(uint8_t const& value) {
  fatemeh_packet_header_tos = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::tosIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsettos() {
  fatemeh_packet_headerIsSet = false;
}




uint16_t PacketReport::getheaderlength() const {
  return fatemeh_packet_header_length;
}
void PacketReport::setheaderlength(uint16_t const& value) {
  fatemeh_packet_header_length = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::headerlengthIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsetheaderlength() {
  fatemeh_packet_headerIsSet = false;
}

uint16_t PacketReport::getfrgID() const {
  return fatemeh_packet_header_fragment_id;
}
void PacketReport::setfrgID(uint16_t const& value) {
  fatemeh_packet_header_fragment_id = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::frgIDIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsetfrgID() {
  fatemeh_packet_headerIsSet = false;
}

uint16_t PacketReport::getflags() const {
  return fatemeh_packet_header_flags_and_fragment_offset;
}
void PacketReport::setflags(uint16_t const& value) {
  fatemeh_packet_header_flags_and_fragment_offset = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::flagsIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsetflags() {
  fatemeh_packet_headerIsSet = false;
}


uint8_t PacketReport::getttl() const {
  return fatemeh_packet_header_ttl;
}
void PacketReport::setttl(uint8_t const& value) {
  fatemeh_packet_header_ttl = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::ttlIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsetttl() {
  fatemeh_packet_headerIsSet = false;
}

uint8_t PacketReport::getprotocol() const {
  return fatemeh_packet_header_protocol;
}
void PacketReport::setprotocol(uint8_t const& value) {
  fatemeh_packet_header_protocol = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::protocolIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsetprotocol() {
  fatemeh_packet_headerIsSet = false;
}


uint16_t PacketReport::getchecksum() const {
  return fatemeh_packet_header_checksum;
}
void PacketReport::setchecksum(uint16_t const& value) {
  fatemeh_packet_header_checksum = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::checksumIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsetchecksum() {
  fatemeh_packet_headerIsSet = false;
}

uint32_t PacketReport::getsrc() const {
  return fatemeh_packet_header_src;
}
void PacketReport::setsrc(uint32_t const& value) {
  fatemeh_packet_header_src = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::srcIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsetsrc() {
  fatemeh_packet_headerIsSet = false;
}

uint32_t PacketReport::getdst() const {
  return fatemeh_packet_header_dst;
}
void PacketReport::setdst(uint32_t const& value) {
  fatemeh_packet_header_dst = value;
  fatemeh_packet_headerIsSet = true;
}
bool PacketReport::dstIsSet() const {
  return fatemeh_packet_headerIsSet;
}
void PacketReport::unsetdst() {
  fatemeh_packet_headerIsSet = false;
}





// pfcp::usage_report_trigger_t UsageReport::getURTrigger() const {
//   return m_urTrig;
// }
// void UsageReport::setURTrigger(pfcp::usage_report_trigger_t const& value) {
//   m_urTrig      = value;
//   m_urTrigIsSet = true;
// }
// bool UsageReport::urTriggerIsSet() const {
//   return m_urTrigIsSet;
// }
// void UsageReport::unsetURTrigger() {
//   m_urTrigIsSet = false;
// }

}  // namespace model
}  // namespace smf_server
}  // namespace oai
