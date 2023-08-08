/**
 * NRF NFManagement Service
 * NRF NFManagement Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

#include "PlmnSnssai.h"

namespace oai {
namespace smf_server {
namespace model {

PlmnSnssai::PlmnSnssai() {}

PlmnSnssai::~PlmnSnssai() {}

void PlmnSnssai::validate() {
  // TODO: implement validation
}

void to_json(nlohmann::json& j, const PlmnSnssai& o) {
  j               = nlohmann::json();
  j["plmnId"]     = o.m_PlmnId;
  j["sNssaiList"] = o.m_SNssaiList;
}

void from_json(const nlohmann::json& j, PlmnSnssai& o) {
  j.at("plmnId").get_to(o.m_PlmnId);
  j.at("sNssaiList").get_to(o.m_SNssaiList);
}

oai::model::common::PlmnId PlmnSnssai::getPlmnId() const {
  return m_PlmnId;
}
void PlmnSnssai::setPlmnId(oai::model::common::PlmnId const& value) {
  m_PlmnId = value;
}
std::vector<oai::model::common::Snssai>& PlmnSnssai::getSNssaiList() {
  return m_SNssaiList;
}
void PlmnSnssai::setSNssaiList(
    std::vector<oai::model::common::Snssai> const& value) {
  m_SNssaiList = value;
}

}  // namespace model
}  // namespace smf_server
}  // namespace oai
