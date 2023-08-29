/**
 * Nsmf_PDUSession
 * SMF PDU Session Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "VsmfUpdateError.h"

namespace oai {
namespace smf_server {
namespace model {

using namespace oai::model::common;

VsmfUpdateError::VsmfUpdateError() {
  m_Pti                        = 0;
  m_PtiIsSet                   = false;
  m_N1smCause                  = "";
  m_N1smCauseIsSet             = false;
  m_N1SmInfoFromUeIsSet        = false;
  m_UnknownN1SmInfoIsSet       = false;
  m_FailedToAssignEbiListIsSet = false;
  m_NgApCauseIsSet             = false;
  m__5gMmCauseValue            = 0;
  m__5gMmCauseValueIsSet       = false;
  m_RecoveryTime               = "";
  m_RecoveryTimeIsSet          = false;
}

VsmfUpdateError::~VsmfUpdateError() {}

void VsmfUpdateError::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const VsmfUpdateError& o) {
  j          = nlohmann::json();
  j["error"] = o.m_Error;
  if (o.ptiIsSet()) j["pti"] = o.m_Pti;
  if (o.n1smCauseIsSet()) j["n1smCause"] = o.m_N1smCause;
  if (o.n1SmInfoFromUeIsSet()) j["n1SmInfoFromUe"] = o.m_N1SmInfoFromUe;
  if (o.unknownN1SmInfoIsSet()) j["unknownN1SmInfo"] = o.m_UnknownN1SmInfo;
  if (o.failedToAssignEbiListIsSet())
    j["failedToAssignEbiList"] = o.m_FailedToAssignEbiList;
  if (o.ngApCauseIsSet()) j["ngApCause"] = o.m_NgApCause;
  if (o._5gMmCauseValueIsSet()) j["5gMmCauseValue"] = o.m__5gMmCauseValue;
  if (o.recoveryTimeIsSet()) j["recoveryTime"] = o.m_RecoveryTime;
}

void from_json(const nlohmann::json& j, VsmfUpdateError& o) {
  j.at("error").get_to(o.m_Error);
  if (j.find("pti") != j.end()) {
    j.at("pti").get_to(o.m_Pti);
    o.m_PtiIsSet = true;
  }
  if (j.find("n1smCause") != j.end()) {
    j.at("n1smCause").get_to(o.m_N1smCause);
    o.m_N1smCauseIsSet = true;
  }
  if (j.find("n1SmInfoFromUe") != j.end()) {
    j.at("n1SmInfoFromUe").get_to(o.m_N1SmInfoFromUe);
    o.m_N1SmInfoFromUeIsSet = true;
  }
  if (j.find("unknownN1SmInfo") != j.end()) {
    j.at("unknownN1SmInfo").get_to(o.m_UnknownN1SmInfo);
    o.m_UnknownN1SmInfoIsSet = true;
  }
  if (j.find("failedToAssignEbiList") != j.end()) {
    j.at("failedToAssignEbiList").get_to(o.m_FailedToAssignEbiList);
    o.m_FailedToAssignEbiListIsSet = true;
  }
  if (j.find("ngApCause") != j.end()) {
    j.at("ngApCause").get_to(o.m_NgApCause);
    o.m_NgApCauseIsSet = true;
  }
  if (j.find("5gMmCauseValue") != j.end()) {
    j.at("5gMmCauseValue").get_to(o.m__5gMmCauseValue);
    o.m__5gMmCauseValueIsSet = true;
  }
  if (j.find("recoveryTime") != j.end()) {
    j.at("recoveryTime").get_to(o.m_RecoveryTime);
    o.m_RecoveryTimeIsSet = true;
  }
}

ProblemDetails VsmfUpdateError::getError() const {
  return m_Error;
}
void VsmfUpdateError::setError(ProblemDetails const& value) {
  m_Error = value;
}
int32_t VsmfUpdateError::getPti() const {
  return m_Pti;
}
void VsmfUpdateError::setPti(int32_t const value) {
  m_Pti      = value;
  m_PtiIsSet = true;
}
bool VsmfUpdateError::ptiIsSet() const {
  return m_PtiIsSet;
}
void VsmfUpdateError::unsetPti() {
  m_PtiIsSet = false;
}
std::string VsmfUpdateError::getN1smCause() const {
  return m_N1smCause;
}
void VsmfUpdateError::setN1smCause(std::string const& value) {
  m_N1smCause      = value;
  m_N1smCauseIsSet = true;
}
bool VsmfUpdateError::n1smCauseIsSet() const {
  return m_N1smCauseIsSet;
}
void VsmfUpdateError::unsetN1smCause() {
  m_N1smCauseIsSet = false;
}
RefToBinaryData VsmfUpdateError::getN1SmInfoFromUe() const {
  return m_N1SmInfoFromUe;
}
void VsmfUpdateError::setN1SmInfoFromUe(RefToBinaryData const& value) {
  m_N1SmInfoFromUe      = value;
  m_N1SmInfoFromUeIsSet = true;
}
bool VsmfUpdateError::n1SmInfoFromUeIsSet() const {
  return m_N1SmInfoFromUeIsSet;
}
void VsmfUpdateError::unsetN1SmInfoFromUe() {
  m_N1SmInfoFromUeIsSet = false;
}
RefToBinaryData VsmfUpdateError::getUnknownN1SmInfo() const {
  return m_UnknownN1SmInfo;
}
void VsmfUpdateError::setUnknownN1SmInfo(RefToBinaryData const& value) {
  m_UnknownN1SmInfo      = value;
  m_UnknownN1SmInfoIsSet = true;
}
bool VsmfUpdateError::unknownN1SmInfoIsSet() const {
  return m_UnknownN1SmInfoIsSet;
}
void VsmfUpdateError::unsetUnknownN1SmInfo() {
  m_UnknownN1SmInfoIsSet = false;
}
std::vector<int32_t>& VsmfUpdateError::getFailedToAssignEbiList() {
  return m_FailedToAssignEbiList;
}
bool VsmfUpdateError::failedToAssignEbiListIsSet() const {
  return m_FailedToAssignEbiListIsSet;
}
void VsmfUpdateError::unsetFailedToAssignEbiList() {
  m_FailedToAssignEbiListIsSet = false;
}
NgApCause VsmfUpdateError::getNgApCause() const {
  return m_NgApCause;
}
void VsmfUpdateError::setNgApCause(NgApCause const& value) {
  m_NgApCause      = value;
  m_NgApCauseIsSet = true;
}
bool VsmfUpdateError::ngApCauseIsSet() const {
  return m_NgApCauseIsSet;
}
void VsmfUpdateError::unsetNgApCause() {
  m_NgApCauseIsSet = false;
}
int32_t VsmfUpdateError::get5gMmCauseValue() const {
  return m__5gMmCauseValue;
}
void VsmfUpdateError::set5gMmCauseValue(int32_t const value) {
  m__5gMmCauseValue      = value;
  m__5gMmCauseValueIsSet = true;
}
bool VsmfUpdateError::_5gMmCauseValueIsSet() const {
  return m__5gMmCauseValueIsSet;
}
void VsmfUpdateError::unset_5gMmCauseValue() {
  m__5gMmCauseValueIsSet = false;
}
std::string VsmfUpdateError::getRecoveryTime() const {
  return m_RecoveryTime;
}
void VsmfUpdateError::setRecoveryTime(std::string const& value) {
  m_RecoveryTime      = value;
  m_RecoveryTimeIsSet = true;
}
bool VsmfUpdateError::recoveryTimeIsSet() const {
  return m_RecoveryTimeIsSet;
}
void VsmfUpdateError::unsetRecoveryTime() {
  m_RecoveryTimeIsSet = false;
}

}  // namespace model
}  // namespace smf_server
}  // namespace oai
