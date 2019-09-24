#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "NASKeySetIdentifier.h"
#include "ServiceType.h"
#include "_5GSMobileIdentity.h"
#include "UplinkDataStatus.h"
#include "PDUSessionStatus.h"
#include "AllowedPDUSessionStatus.h"
#include "NASMessageContainer.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define SERVICE_REQUEST_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		NAS_KEY_SET_IDENTIFIER_MINIMUM_LENGTH + \
		SERVICE_TYPE_MINIMUM_LENGTH + \
		_5GS_MOBILE_IDENTITY_MINIMUM_LENGTH + \
		UPLINK_DATA_STATUS_MINIMUM_LENGTH + \
		PDU_SESSION_STATUS_MINIMUM_LENGTH + \
		ALLOWED_PDU_SESSION_STATUS_MINIMUM_LENGTH + \
		NAS_MESSAGE_CONTAINER_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define SERVICE_REQUEST_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		NAS_KEY_SET_IDENTIFIER_MAXIMUM_LENGTH + \
		SERVICE_TYPE_MAXIMUM_LENGTH + \
		_5GS_MOBILE_IDENTITY_MAXIMUM_LENGTH + \
		UPLINK_DATA_STATUS_MAXIMUM_LENGTH + \
		PDU_SESSION_STATUS_MAXIMUM_LENGTH + \
		ALLOWED_PDU_SESSION_STATUS_MAXIMUM_LENGTH + \
		NAS_MESSAGE_CONTAINER_MAXIMUM_LENGTH + \
0)

typedef struct service_request_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
	NASKeySetIdentifier naskeysetidentifier;
	ServiceType servicetype;
	_5GSMobileIdentity _5gsmobileidentity;
	UplinkDataStatus uplinkdatastatus;
	PDUSessionStatus pdusessionstatus;
	AllowedPDUSessionStatus allowedpdusessionstatus;
	NASMessageContainer nasmessagecontainer;
}service_request_msg;


int decode_service_request(service_request_msg *servicerequest, uint8_t *buffer, uint32_t len);
int encode_service_request(service_request_msg *servicerequest, uint8_t *buffer, uint32_t len);
