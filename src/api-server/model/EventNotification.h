/**
 * Nsmf_EventExposure
 * Session Management Event Exposure Service. © 2019, 3GPP Organizational
 * Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * EventNotification.h
 *
 *
 */

#ifndef EventNotification_H_
#define EventNotification_H_

#include "DnaiChangeType.h"
#include "DddStatus.h"
#include <string>
#include "Ipv6Prefix.h"
#include "SmfEvent.h"
#include "PlmnId.h"
#include "RouteToLocation.h"
#include "AccessType.h"
#include "UsageReport.h"
#include "PacketReport.h"
#include <nlohmann/json.hpp>

namespace oai {
namespace smf_server {
namespace model {

/// <summary>
///
/// </summary>
class EventNotification {
 public:
  EventNotification();
  virtual ~EventNotification();

  void validate();

  /////////////////////////////////////////////
  /// EventNotification members

  /// <summary>
  ///
  /// </summary>
  SmfEvent getEvent() const;
  void setEvent(SmfEvent const& value);
  /// <summary>
  ///
  /// </summary>
  std::string getTimeStamp() const;
  void setTimeStamp(std::string const& value);
  /// <summary>
  ///
  /// </summary>
  std::string getSupi() const;
  void setSupi(std::string const& value);
  bool supiIsSet() const;
  void unsetSupi();
  /// <summary>
  ///
  /// </summary>
  std::string getGpsi() const;
  void setGpsi(std::string const& value);
  bool gpsiIsSet() const;
  void unsetGpsi();
  /// <summary>
  ///
  /// </summary>
  std::string getSourceDnai() const;
  void setSourceDnai(std::string const& value);
  bool sourceDnaiIsSet() const;
  void unsetSourceDnai();
  /// <summary>
  ///
  /// </summary>
  std::string getTargetDnai() const;
  void setTargetDnai(std::string const& value);
  bool targetDnaiIsSet() const;
  void unsetTargetDnai();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::DnaiChangeType getDnaiChgType() const;
  void setDnaiChgType(oai::model::common::DnaiChangeType const& value);
  bool dnaiChgTypeIsSet() const;
  void unsetDnaiChgType();
  /// <summary>
  ///
  /// </summary>
  std::string getSourceUeIpv4Addr() const;
  void setSourceUeIpv4Addr(std::string const& value);
  bool sourceUeIpv4AddrIsSet() const;
  void unsetSourceUeIpv4Addr();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::Ipv6Prefix getSourceUeIpv6Prefix() const;
  void setSourceUeIpv6Prefix(oai::model::common::Ipv6Prefix const& value);
  bool sourceUeIpv6PrefixIsSet() const;
  void unsetSourceUeIpv6Prefix();
  /// <summary>
  ///
  /// </summary>
  std::string getTargetUeIpv4Addr() const;
  void setTargetUeIpv4Addr(std::string const& value);
  bool targetUeIpv4AddrIsSet() const;
  void unsetTargetUeIpv4Addr();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::Ipv6Prefix getTargetUeIpv6Prefix() const;
  void setTargetUeIpv6Prefix(oai::model::common::Ipv6Prefix const& value);
  bool targetUeIpv6PrefixIsSet() const;
  void unsetTargetUeIpv6Prefix();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::RouteToLocation getSourceTraRouting() const;
  void setSourceTraRouting(oai::model::common::RouteToLocation const& value);
  bool sourceTraRoutingIsSet() const;
  void unsetSourceTraRouting();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::RouteToLocation getTargetTraRouting() const;
  void setTargetTraRouting(oai::model::common::RouteToLocation const& value);
  bool targetTraRoutingIsSet() const;
  void unsetTargetTraRouting();
  /// <summary>
  ///
  /// </summary>
  std::string getUeMac() const;
  void setUeMac(std::string const& value);
  bool ueMacIsSet() const;
  void unsetUeMac();
  /// <summary>
  ///
  /// </summary>
  std::string getAdIpv4Addr() const;
  void setAdIpv4Addr(std::string const& value);
  bool adIpv4AddrIsSet() const;
  void unsetAdIpv4Addr();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::Ipv6Prefix getAdIpv6Prefix() const;
  void setAdIpv6Prefix(oai::model::common::Ipv6Prefix const& value);
  bool adIpv6PrefixIsSet() const;
  void unsetAdIpv6Prefix();
  /// <summary>
  ///
  /// </summary>
  std::string getReIpv4Addr() const;
  void setReIpv4Addr(std::string const& value);
  bool reIpv4AddrIsSet() const;
  void unsetReIpv4Addr();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::Ipv6Prefix getReIpv6Prefix() const;
  void setReIpv6Prefix(oai::model::common::Ipv6Prefix const& value);
  bool reIpv6PrefixIsSet() const;
  void unsetReIpv6Prefix();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::PlmnId getPlmnId() const;
  void setPlmnId(oai::model::common::PlmnId const& value);
  bool plmnIdIsSet() const;
  void unsetPlmnId();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::AccessType getAccType() const;
  void setAccType(oai::model::common::AccessType const& value);
  bool accTypeIsSet() const;
  void unsetAccType();
  /// <summary>
  ///
  /// </summary>
  int32_t getPduSeId() const;
  void setPduSeId(int32_t const value);
  bool pduSeIdIsSet() const;
  void unsetPduSeId();
  /// <summary>
  ///
  /// </summary>
  DddStatus getDddStatus() const;
  void setDddStatus(DddStatus const& value);
  bool dddStatusIsSet() const;
  void unsetDddStatus();
  /// <summary>
  ///
  /// </summary>
  std::string getMaxWaitTime() const;
  void setMaxWaitTime(std::string const& value);
  bool maxWaitTimeIsSet() const;
  void unsetMaxWaitTime();
  /// <summary>
  ///
  /// </summary>
  // [FATEMEH]: might be intersting
  UsageReport getUsageReport() const;
  void setUsageReport(UsageReport const& value);
  bool usageReportIsSet() const;
  void unsetUsageReport();

  PacketReport getPacketReport() const;
  void setPacketReport(PacketReport const& value);
  bool PacketReportIsSet() const;
  void unsetPacketReport();

  friend void to_json(nlohmann::json& j, const EventNotification& o);
  friend void from_json(const nlohmann::json& j, EventNotification& o);

 protected:
  SmfEvent m_Event;

  std::string m_TimeStamp;

  std::string m_Supi;
  bool m_SupiIsSet;
  std::string m_Gpsi;
  bool m_GpsiIsSet;
  std::string m_SourceDnai;
  bool m_SourceDnaiIsSet;
  std::string m_TargetDnai;
  bool m_TargetDnaiIsSet;
  oai::model::common::DnaiChangeType m_DnaiChgType;
  bool m_DnaiChgTypeIsSet;
  std::string m_SourceUeIpv4Addr;
  bool m_SourceUeIpv4AddrIsSet;
  oai::model::common::Ipv6Prefix m_SourceUeIpv6Prefix;
  bool m_SourceUeIpv6PrefixIsSet;
  std::string m_TargetUeIpv4Addr;
  bool m_TargetUeIpv4AddrIsSet;
  oai::model::common::Ipv6Prefix m_TargetUeIpv6Prefix;
  bool m_TargetUeIpv6PrefixIsSet;
  oai::model::common::RouteToLocation m_SourceTraRouting;
  bool m_SourceTraRoutingIsSet;
  oai::model::common::RouteToLocation m_TargetTraRouting;
  bool m_TargetTraRoutingIsSet;
  std::string m_UeMac;
  bool m_UeMacIsSet;
  std::string m_AdIpv4Addr;
  bool m_AdIpv4AddrIsSet;
  oai::model::common::Ipv6Prefix m_AdIpv6Prefix;
  bool m_AdIpv6PrefixIsSet;
  std::string m_ReIpv4Addr;
  bool m_ReIpv4AddrIsSet;
  oai::model::common::Ipv6Prefix m_ReIpv6Prefix;
  bool m_ReIpv6PrefixIsSet;
  oai::model::common::PlmnId m_PlmnId;
  bool m_PlmnIdIsSet;
  oai::model::common::AccessType m_AccType;
  bool m_AccTypeIsSet;
  int32_t m_PduSeId;
  bool m_PduSeIdIsSet;
  DddStatus m_DddStatus;
  bool m_DddStatusIsSet;
  std::string m_MaxWaitTime;
  bool m_MaxWaitTimeIsSet;
  // [FATEMEH]: might be intersting!
  UsageReport m_usageReport;
  bool m_usageReportIsSet;
  PacketReport m_packetReport;
  bool m_packetReportIsSet;
};

}  // namespace model
}  // namespace smf_server
}  // namespace oai

#endif /* EventNotification_H_ */
