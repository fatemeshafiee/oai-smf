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
/*
 * PlmnSnssai.h
 *
 *
 */

#ifndef PlmnSnssai_H_
#define PlmnSnssai_H_

#include "PlmnId.h"
#include "Snssai.h"
#include <vector>
#include <nlohmann/json.hpp>

namespace oai {
namespace smf_server {
namespace model {

/// <summary>
///
/// </summary>
class PlmnSnssai {
 public:
  PlmnSnssai();
  virtual ~PlmnSnssai();

  void validate();

  /////////////////////////////////////////////
  /// PlmnSnssai members

  /// <summary>
  ///
  /// </summary>
  PlmnId getPlmnId() const;
  void setPlmnId(PlmnId const& value);
  /// <summary>
  ///
  /// </summary>
  std::vector<oai::model::common::Snssai>& getSNssaiList();
  void setSNssaiList(std::vector<oai::model::common::Snssai> const& value);

  friend void to_json(nlohmann::json& j, const PlmnSnssai& o);
  friend void from_json(const nlohmann::json& j, PlmnSnssai& o);

 protected:
  PlmnId m_PlmnId;

  std::vector<oai::model::common::Snssai> m_SNssaiList;
};

}  // namespace model
}  // namespace smf_server
}  // namespace oai

#endif /* PlmnSnssai_H_ */
