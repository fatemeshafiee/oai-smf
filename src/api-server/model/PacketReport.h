/**
 * Nsmf_EventExposure
 *
 * PacketReport.h
 */

#ifndef PacketReport_H_
#define PacketReport_H_

#include "msg_pfcp.hpp"
#include <nlohmann/json.hpp>

namespace oai {
namespace smf_server {
namespace model {

// TODO: Redefine in separate files
//enum PacketReportTrigger { PERIO = 1, VOLTH, TIMTH, VOLQU, TIMQU };

/// <summary>
///
/// </summary>
class PacketReport {
 public:
  PacketReport();
  virtual ~PacketReport();

  void validate();

  /////////////////////////////////////////////
  /// PacketReport members

  /// <summary>
  ///
  /// </summary>
  int64_t getSEndID() const;
  void setSEndID(int64_t const& value);
  bool SEndIDIsSet() const;
  void unsetSEndID();

  /// <summary>
  ///
  /// </summary>
  uint8_t getpacket_type() const;
  void setpacket_type(uint8_t const& value);
  bool packet_typeISset() const;
  void unsetpacket_type();
  /// <summary>
  ///
  /// </summary>

  uint16_t getdata_length() const;
  void setdata_length(uint16_t const& value);
  bool lengthIsSet() const;
  void unsetdata_length();
  /// <summary>
  ///
  /// </summary>
 

  std::string getdata_data() const;
  void setdata_data(std::string const& value);
  bool dataIsSet() const;
  void unsetdata_data();
  /// <summary>
  ///
  /// </summary>
  uint8_t getipv() const;
  void setipv(uint8_t const& value);
  bool ipvIsSet() const;
  void unsetipv();

  /// <summary>
  ///
  /// </summary>

  /// <summary>
  ///
  /// </summary>
  uint8_t gettos() const;
  void settos(uint8_t const& value);
  bool tosIsSet() const;
  void unsettos() ;
  /// <summary>

  /// </summary>


  /// <summary>
  ///
  /// </summary>
  uint16_t getheaderlength() const;;
  void setheaderlength(uint16_t const& value);
  bool headerlengthIsSet() const;
  void unsetheaderlength();

  /// <summary>
  ///
  /// </summary>
  uint16_t getfrgID() const;
  void setfrgID(uint16_t const& value);
  bool frgIDIsSet() const;
  void unsetfrgID();
  /// <summary>
  ///
  /// </summary>

  uint16_t getflags() const;
  void setflags(uint16_t const& value);
  bool flagsIsSet() const;
  void unsetflags();
  /// <summary>
  ///
  /// </summary>
  uint8_t getttl() const;
  void setttl(uint8_t const& value);
  bool ttlIsSet() const;
  void unsetttl();
  /// <summary>
  ///
  /// </summary>
  uint8_t getprotocol() const;
  void setprotocol(uint8_t const& value);
  bool protocolIsSet() const;
  void unsetprotocol();
  /// <summary>
  ///
  /// </summary>
  uint16_t getchecksum() const;
  void setchecksum(uint16_t const& value);
  bool checksumIsSet() const;
  void unsetchecksum();
  /// <summary>
  ///
  /// </summary>
  uint32_t getsrc() const;
  void setsrc(uint32_t const& value);
  bool srcIsSet() const;
  void unsetsrc();
  /// <summary>
  ///
  /// </summary>
  uint32_t getdst() const;
  void setdst(uint32_t const& value);
  bool dstIsSet() const;
  void unsetdst(); 
  /// <summary>
  ///
  /// </summary>
  // pfcp::usage_report_trigger_t getURTrigger() const;
  // void setURTrigger(pfcp::usage_report_trigger_t const& value);
  // bool urTriggerIsSet() const;
  // void unsetURTrigger();

  friend void to_json(nlohmann::json& j, const PacketReport& o);
  friend void from_json(const nlohmann::json& j, PacketReport& o);

 protected:
  int64_t m_SEndID;
  bool m_SEndIDIsSet;
  uint8_t fatemeh_packet_type;
  bool fatemeh_packet_typeIsSet;
  uint16_t fatemeh_packet_data_length;
  std::string fatemeh_packet_data_data;
  bool fatemeh_packet_dataIsSet;
  uint8_t   fatemeh_packet_header_ip_version_and_header_length;
  uint8_t   fatemeh_packet_header_tos;
  uint16_t  fatemeh_packet_header_length;
  uint16_t  fatemeh_packet_header_fragment_id;
  uint16_t  fatemeh_packet_header_flags_and_fragment_offset;
  uint8_t   fatemeh_packet_header_ttl;
  uint8_t   fatemeh_packet_header_protocol;
  uint16_t  fatemeh_packet_header_checksum;
  uint32_t fatemeh_packet_header_src;
  uint32_t fatemeh_packet_header_dst;
  bool fatemeh_packet_headerIsSet;

  


  // // UsageReportTrigger m_urTrig;
  // pfcp::usage_report_trigger_t m_urTrig;
  // bool m_urTrigIsSet;
};

}  // namespace model
}  // namespace smf_server
}  // namespace oai

#endif /* PacketReport_H_ */
