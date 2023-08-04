/**
 * Npcf_SMPolicyControl API
 * Session Management Policy Control Service © 2020, 3GPP Organizational
 * Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.1.alpha-5
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */
/*
 * SmPolicyContextData.h
 *
 *
 */

#ifndef SmPolicyContextData_H_
#define SmPolicyContextData_H_

// TODO unsupported models commented out
//#include "AccNetChId.h"
#include "Ambr.h"
#include "AtsssCapability.h"
//#include "SubscribedDefaultQos.h"
#include "RatType.h"
#include <string>
//#include "ServingNfIdentity.h"
//#include "MaPduIndication.h"
#include "Snssai.h"
#include "TraceData.h"
#include <vector>
#include "AccessType.h"
//#include "AccNetChargingAddress.h"
#include "DnnSelectionMode.h"
#include "PlmnIdNid.h"
//#include "QosFlowUsage.h"
#include "Ipv6Prefix.h"
#include "UserLocation.h"
#include "PduSessionType.h"
//#include "AdditionalAccessInfo.h"
#include <nlohmann/json.hpp>

namespace oai {
namespace smf_server {
namespace model {

/// <summary>
///
/// </summary>
class SmPolicyContextData {
 public:
  SmPolicyContextData();
  virtual ~SmPolicyContextData() = default;

  /// <summary>
  /// Validate the current data in the model. Throws a ValidationException on
  /// failure.
  /// </summary>
  void validate() const;

  /// <summary>
  /// Validate the current data in the model. Returns false on error and writes
  /// an error message into the given stringstream.
  /// </summary>
  bool validate(std::stringstream& msg) const;

  /// <summary>
  /// Helper overload for validate. Used when one model stores another model and
  /// calls it's validate. Not meant to be called outside that case.
  /// </summary>
  bool validate(std::stringstream& msg, const std::string& pathPrefix) const;

  bool operator==(const SmPolicyContextData& rhs) const;
  bool operator!=(const SmPolicyContextData& rhs) const;

  /////////////////////////////////////////////
  /// SmPolicyContextData members

  /// <summary>
  ///
  /// </summary>
  /*
  AccNetChId getAccNetChId() const;
  void setAccNetChId(AccNetChId const& value);
  bool accNetChIdIsSet() const;
  void unsetAccNetChId();
  /// <summary>
  ///
  /// </summary>
  AccNetChargingAddress getChargEntityAddr() const;
  void setChargEntityAddr(AccNetChargingAddress const& value);
  bool chargEntityAddrIsSet() const;
  void unsetChargEntityAddr();
  */
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
  std::string getSupi() const;
  void setSupi(std::string const& value);
  /// <summary>
  ///
  /// </summary>
  std::vector<std::string> getInterGrpIds() const;
  void setInterGrpIds(std::vector<std::string> const& value);
  bool interGrpIdsIsSet() const;
  void unsetInterGrpIds();
  /// <summary>
  ///
  /// </summary>
  int32_t getPduSessionId() const;
  void setPduSessionId(int32_t const value);
  /// <summary>
  ///
  /// </summary>
  PduSessionType getPduSessionType() const;
  void setPduSessionType(PduSessionType const& value);
  /// <summary>
  ///
  /// </summary>
  std::string getChargingcharacteristics() const;
  void setChargingcharacteristics(std::string const& value);
  bool chargingcharacteristicsIsSet() const;
  void unsetChargingcharacteristics();
  /// <summary>
  ///
  /// </summary>
  std::string getDnn() const;
  void setDnn(std::string const& value);
  /// <summary>
  ///
  /// </summary>
  DnnSelectionMode getDnnSelMode() const;
  void setDnnSelMode(DnnSelectionMode const& value);
  bool dnnSelModeIsSet() const;
  void unsetDnnSelMode();
  /// <summary>
  ///
  /// </summary>
  std::string getNotificationUri() const;
  void setNotificationUri(std::string const& value);
  /// <summary>
  ///
  /// </summary>
  AccessType getAccessType() const;
  void setAccessType(AccessType const& value);
  bool accessTypeIsSet() const;
  void unsetAccessType();
  /// <summary>
  ///
  /// </summary>
  RatType getRatType() const;
  void setRatType(RatType const& value);
  bool ratTypeIsSet() const;
  void unsetRatType();
  /// <summary>
  ///
  /// </summary>
  /*
  AdditionalAccessInfo getAddAccessInfo() const;
  void setAddAccessInfo(AdditionalAccessInfo const& value);
  bool addAccessInfoIsSet() const;
  void unsetAddAccessInfo();
  */
  /// <summary>
  ///
  /// </summary>
  PlmnIdNid getServingNetwork() const;
  void setServingNetwork(PlmnIdNid const& value);
  bool servingNetworkIsSet() const;
  void unsetServingNetwork();
  /// <summary>
  ///
  /// </summary>
  UserLocation getUserLocationInfo() const;
  void setUserLocationInfo(UserLocation const& value);
  bool userLocationInfoIsSet() const;
  void unsetUserLocationInfo();
  /// <summary>
  ///
  /// </summary>
  std::string getUeTimeZone() const;
  void setUeTimeZone(std::string const& value);
  bool ueTimeZoneIsSet() const;
  void unsetUeTimeZone();
  /// <summary>
  ///
  /// </summary>
  std::string getPei() const;
  void setPei(std::string const& value);
  bool peiIsSet() const;
  void unsetPei();
  /// <summary>
  ///
  /// </summary>
  std::string getIpv4Address() const;
  void setIpv4Address(std::string const& value);
  bool ipv4AddressIsSet() const;
  void unsetIpv4Address();
  /// <summary>
  ///
  /// </summary>
  /*
  Ipv6Prefix getIpv6AddressPrefix() const;
  void setIpv6AddressPrefix(Ipv6Prefix const& value);
  bool ipv6AddressPrefixIsSet() const;
  void unsetIpv6AddressPrefix();
  */
  /// <summary>
  /// Indicates the IPv4 address domain
  /// </summary>
  std::string getIpDomain() const;
  void setIpDomain(std::string const& value);
  bool ipDomainIsSet() const;
  void unsetIpDomain();
  /// <summary>
  ///
  /// </summary>
  /*
  Ambr getSubsSessAmbr() const;
  void setSubsSessAmbr(Ambr const& value);
  bool subsSessAmbrIsSet() const;
  void unsetSubsSessAmbr();
  */
  /// <summary>
  /// Indicates the DN-AAA authorization profile index
  /// </summary>
  std::string getAuthProfIndex() const;
  void setAuthProfIndex(std::string const& value);
  bool authProfIndexIsSet() const;
  void unsetAuthProfIndex();
  /// <summary>
  ///
  /// </summary>
  /*
  SubscribedDefaultQos getSubsDefQos() const;
  void setSubsDefQos(SubscribedDefaultQos const& value);
  bool subsDefQosIsSet() const;
  void unsetSubsDefQos();
  */
  /// <summary>
  /// Contains the number of supported packet filter for signalled QoS rules.
  /// </summary>
  int32_t getNumOfPackFilter() const;
  void setNumOfPackFilter(int32_t const value);
  bool numOfPackFilterIsSet() const;
  void unsetNumOfPackFilter();
  /// <summary>
  /// If it is included and set to true, the online charging is applied to the
  /// PDU session.
  /// </summary>
  bool isOnline() const;
  void setOnline(bool const value);
  bool onlineIsSet() const;
  void unsetOnline();
  /// <summary>
  /// If it is included and set to true, the offline charging is applied to the
  /// PDU session.
  /// </summary>
  bool isOffline() const;
  void setOffline(bool const value);
  bool offlineIsSet() const;
  void unsetOffline();
  /// <summary>
  /// If it is included and set to true, the 3GPP PS Data Off is activated by
  /// the UE.
  /// </summary>
  bool isR3gppPsDataOffStatus() const;
  void setR3gppPsDataOffStatus(bool const value);
  bool r3gppPsDataOffStatusIsSet() const;
  void unsetr_3gppPsDataOffStatus();
  /// <summary>
  /// If it is included and set to true, the reflective QoS is supported by the
  /// UE.
  /// </summary>
  bool isRefQosIndication() const;
  void setRefQosIndication(bool const value);
  bool refQosIndicationIsSet() const;
  void unsetRefQosIndication();
  /// <summary>
  ///
  /// </summary>
  TraceData getTraceReq() const;
  void setTraceReq(TraceData const& value);
  bool traceReqIsSet() const;
  void unsetTraceReq();
  /// <summary>
  ///
  /// </summary>
  oai::model::common::Snssai getSliceInfo() const;
  void setSliceInfo(oai::model::common::Snssai const& value);
  /// <summary>
  ///
  /// </summary>
  /*
  QosFlowUsage getQosFlowUsage() const;
  void setQosFlowUsage(QosFlowUsage const& value);
  bool qosFlowUsageIsSet() const;
  void unsetQosFlowUsage();
  /// <summary>
  ///
  /// </summary>
  ServingNfIdentity getServNfId() const;
  void setServNfId(ServingNfIdentity const& value);
  bool servNfIdIsSet() const;
  void unsetServNfId();
  */
  /// <summary>
  ///
  /// </summary>
  std::string getSuppFeat() const;
  void setSuppFeat(std::string const& value);
  bool suppFeatIsSet() const;
  void unsetSuppFeat();
  /// <summary>
  ///
  /// </summary>
  std::string getSmfId() const;
  void setSmfId(std::string const& value);
  bool smfIdIsSet() const;
  void unsetSmfId();
  /// <summary>
  ///
  /// </summary>
  std::string getRecoveryTime() const;
  void setRecoveryTime(std::string const& value);
  bool recoveryTimeIsSet() const;
  void unsetRecoveryTime();
  /// <summary>
  ///
  /// </summary>
  /*
  MaPduIndication getMaPduInd() const;
  void setMaPduInd(MaPduIndication const& value);
  bool maPduIndIsSet() const;
  void unsetMaPduInd();
  /// <summary>
  ///
  /// </summary>
  AtsssCapability getAtsssCapab() const;
  void setAtsssCapab(AtsssCapability const& value);
  bool atsssCapabIsSet() const;
  void unsetAtsssCapab();
  */

  friend void to_json(nlohmann::json& j, const SmPolicyContextData& o);
  friend void from_json(const nlohmann::json& j, SmPolicyContextData& o);

 protected:
  // AccNetChId m_AccNetChId;
  // bool m_AccNetChIdIsSet;
  // AccNetChargingAddress m_ChargEntityAddr;
  // bool m_ChargEntityAddrIsSet;
  std::string m_Gpsi;
  bool m_GpsiIsSet;
  std::string m_Supi;

  std::vector<std::string> m_InterGrpIds;
  bool m_InterGrpIdsIsSet;
  int32_t m_PduSessionId;

  PduSessionType m_PduSessionType;

  std::string m_Chargingcharacteristics;
  bool m_ChargingcharacteristicsIsSet;
  std::string m_Dnn;

  DnnSelectionMode m_DnnSelMode;
  bool m_DnnSelModeIsSet;
  std::string m_NotificationUri;

  AccessType m_AccessType;
  bool m_AccessTypeIsSet;
  RatType m_RatType;
  bool m_RatTypeIsSet;
  // AdditionalAccessInfo m_AddAccessInfo;
  // bool m_AddAccessInfoIsSet;
  PlmnIdNid m_ServingNetwork;
  bool m_ServingNetworkIsSet;
  UserLocation m_UserLocationInfo;
  bool m_UserLocationInfoIsSet;
  std::string m_UeTimeZone;
  bool m_UeTimeZoneIsSet;
  std::string m_Pei;
  bool m_PeiIsSet;
  std::string m_Ipv4Address;
  bool m_Ipv4AddressIsSet;
  // Ipv6Prefix m_Ipv6AddressPrefix;
  // bool m_Ipv6AddressPrefixIsSet;
  std::string m_IpDomain;
  bool m_IpDomainIsSet;
  // Ambr m_SubsSessAmbr;
  // bool m_SubsSessAmbrIsSet;
  std::string m_AuthProfIndex;
  bool m_AuthProfIndexIsSet;
  // SubscribedDefaultQos m_SubsDefQos;
  // bool m_SubsDefQosIsSet;
  int32_t m_NumOfPackFilter;
  bool m_NumOfPackFilterIsSet;
  bool m_Online;
  bool m_OnlineIsSet;
  bool m_Offline;
  bool m_OfflineIsSet;
  bool m_r_3gppPsDataOffStatus;
  bool m_r_3gppPsDataOffStatusIsSet;
  bool m_RefQosIndication;
  bool m_RefQosIndicationIsSet;
  TraceData m_TraceReq;
  bool m_TraceReqIsSet;
  oai::model::common::Snssai m_SliceInfo;

  // QosFlowUsage m_QosFlowUsage;
  // bool m_QosFlowUsageIsSet;
  // ServingNfIdentity m_ServNfId;
  // bool m_ServNfIdIsSet;
  std::string m_SuppFeat;
  bool m_SuppFeatIsSet;
  std::string m_SmfId;
  bool m_SmfIdIsSet;
  std::string m_RecoveryTime;
  bool m_RecoveryTimeIsSet;
  // MaPduIndication m_MaPduInd;
  // bool m_MaPduIndIsSet;
  // AtsssCapability m_AtsssCapab;
  // bool m_AtsssCapabIsSet;
};

}  // namespace model
}  // namespace smf_server
}  // namespace oai
#endif /* SmPolicyContextData_H_ */
