/**
* Nsmf_EventExposure
* Session Management Event Exposure Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved. 
*
* The version of the OpenAPI document: 1.1.0.alpha-1
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/


#include "NsmfEventExposureNotification.h"

namespace oai {
namespace smf_server {
namespace model {

NsmfEventExposureNotification::NsmfEventExposureNotification()
{
    m_NotifId = "";
    
}

NsmfEventExposureNotification::~NsmfEventExposureNotification()
{
}

void NsmfEventExposureNotification::validate()
{
    // TODO: implement validation
}

void to_json(nlohmann::json& j, const NsmfEventExposureNotification& o)
{
    j = nlohmann::json();
    j["notifId"] = o.m_NotifId;
    j["eventNotifs"] = o.m_EventNotifs;
}

void from_json(const nlohmann::json& j, NsmfEventExposureNotification& o)
{
    j.at("notifId").get_to(o.m_NotifId);
    j.at("eventNotifs").get_to(o.m_EventNotifs);
}

std::string NsmfEventExposureNotification::getNotifId() const
{
    return m_NotifId;
}
void NsmfEventExposureNotification::setNotifId(std::string const& value)
{
    m_NotifId = value;
}
std::vector<EventNotification>& NsmfEventExposureNotification::getEventNotifs()
{
    return m_EventNotifs;
}
void NsmfEventExposureNotification::setEventNotifs(std::vector<EventNotification> const& value)
{
    m_EventNotifs = value;
}

}
}
}

