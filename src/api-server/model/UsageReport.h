/**
 * Nsmf_EventExposure
 * 
 * UsageReport.h
 */

#ifndef UsageReport_H_
#define UsageReport_H_

#include "msg_pfcp.hpp"
#include <nlohmann/json.hpp>

namespace oai {
namespace smf_server {
namespace model {

/// <summary>
///
/// </summary>
class UsageReport {
 public:
  UsageReport();
  virtual ~UsageReport();

  void validate();

  /////////////////////////////////////////////
  /// UsageReport members

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
  int32_t geturSeqN() const;
  void seturSeqN(int32_t const& value);
  bool urSeqNIsSet() const;
  void unseturSeqN();

  /// <summary>
  ///
  /// </summary>
  int32_t getDuration() const;
  void setDuration(int32_t const& value);
  bool durationIsSet() const;
  void unsetDuration();

  /// <summary>
  ///
  /// </summary>
  int64_t getTotNoP() const;
  void setTotNoP(int64_t const& value);
  bool totNoPIsSet() const;
  void unsetTotNoP();

  /// <summary>
  ///
  /// </summary>
  int64_t getUlNoP() const;
  void setUlNoP(int64_t const& value);
  bool ulNoPIsSet() const;
  void unsetUlNoP();

  /// <summary>
  ///
  /// </summary>  
  int64_t getDlNoP() const;
  void setDlNoP(int64_t const& value);
  bool dlNoPIsSet() const;
  void unsetDlNoP();

  /// <summary>
  ///
  /// </summary>
  int64_t getTotVol() const;
  void setTotVol(int64_t const& value);
  bool totVolIsSet() const;
  void unsetTotVol();

  /// <summary>
  ///
  /// </summary>
  int64_t getUlVol() const;
  void setUlVol(int64_t const& value);
  bool ulVolIsSet() const;
  void unsetUlVol();

  /// <summary>
  ///
  /// </summary>
  int64_t getDlVol() const;
  void setDlVol(int64_t const& value);
  bool dlVolIsSet() const;
  void unsetDlVol();

  friend void to_json(nlohmann::json& j, const UsageReport& o);
  friend void from_json(const nlohmann::json& j, UsageReport& o);

 protected:

  pfcp::usage_report_within_pfcp_session_deletion_response m_URSessDel;
  bool m_URSessDelIsSet;
  pfcp::usage_report_within_pfcp_session_modification_response m_URSessMod;
  bool m_URSessModIsSet;
  pfcp::usage_report_within_pfcp_session_report_request m_URRequest;
  bool m_URRequestIsSet;

  int64_t m_SEndID;
  bool m_SEndIDIsSet;
  int32_t m_urSeqN;
  bool m_urSeqNIsSet;
  int32_t m_duration;
  bool m_durationIsSet;
  int64_t m_totNoP;
  bool m_totNoPIsSet;
  int64_t m_ulNoP;
  bool m_ulNoPIsSet;
  int64_t m_dlNoP;
  bool m_dlNoPIsSet;
  int64_t m_totVol;
  bool m_totVolIsSet;
  int64_t m_ulVol;
  bool m_ulVolIsSet;
  int64_t m_dlVol;
  bool m_dlVolIsSet;

  // pfcp::usage_report_trigger_t m_urTrig;
  // bool m_urTrigIsSet;
  // pfcp::usage_report_within_pfcp_session_modification_response m_urSessMod;
  // bool m_urSessModIsSet;
};

}  // namespace model
}  // namespace smf_server
}  // namespace oai

#endif /* UsageReport_H_ */
