#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "PDUSessionIdentity.h"
#include "ProcedureTransactionIdentity.h"
#include "MessageType.h"
#include "_5GSMCapability.h"
#include "_5GSMCause.h"
#include "MaximumNumberOfSupportedPacketFilters.h"
#include "AlwaysonPDUSessionRequested.h"
#include "IntergrityProtectionMaximumDataRate.h"
#include "QOSRules.h"
#include "QOSFlowDescriptions.h"
#include "MappedEPSBearerContexts.h"
#include "ExtendedProtocolConfigurationOptions.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define PDU_SESSION_MODIFICATION_REQUEST_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MINIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		_5GSM_CAPABILITY_MINIMUM_LENGTH + \
		_5GSM_CAUSE_MINIMUM_LENGTH + \
		MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS_MINIMUM_LENGTH + \
		ALWAYSON_PDU_SESSION_REQUESTED_MINIMUM_LENGTH + \
		INTERGRITY_PROTECTION_MAXIMUM_DATA_RATE_MINIMUM_LENGTH + \
		QOS_RULES_MINIMUM_LENGTH + \
		QOS_FLOW_DESCRIPTIONS_MINIMUM_LENGTH + \
		MAPPED_EPS_BEARER_CONTEXTS_MINIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define PDU_SESSION_MODIFICATION_REQUEST_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MAXIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		_5GSM_CAPABILITY_MAXIMUM_LENGTH + \
		_5GSM_CAUSE_MAXIMUM_LENGTH + \
		MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS_MAXIMUM_LENGTH + \
		ALWAYSON_PDU_SESSION_REQUESTED_MAXIMUM_LENGTH + \
		INTERGRITY_PROTECTION_MAXIMUM_DATA_RATE_MAXIMUM_LENGTH + \
		QOS_RULES_MAXIMUM_LENGTH + \
		QOS_FLOW_DESCRIPTIONS_MAXIMUM_LENGTH + \
		MAPPED_EPS_BEARER_CONTEXTS_MAXIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MAXIMUM_LENGTH + \
0)

typedef struct pdu_session_modification_request_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	PDUSessionIdentity pdusessionidentity;
	ProcedureTransactionIdentity proceduretransactionidentity;
	MessageType messagetype;
	_5GSMCapability _5gsmcapability;
	_5GSMCause _5gsmcause;
	MaximumNumberOfSupportedPacketFilters maximumnumberofsupportedpacketfilters;
	AlwaysonPDUSessionRequested alwaysonpdusessionrequested;
	IntergrityProtectionMaximumDataRate intergrityprotectionmaximumdatarate;
	QOSRules qosrules;
	QOSFlowDescriptions qosflowdescriptions;
	MappedEPSBearerContexts mappedepsbearercontexts;
	ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions;
}pdu_session_modification_request_msg;


int decode_pdu_session_modification_request(pdu_session_modification_request_msg *pdusessionmodificationrequest, uint8_t *buffer, uint32_t len);
int encode_pdu_session_modification_request(pdu_session_modification_request_msg *pdusessionmodificationrequest, uint8_t *buffer, uint32_t len);
