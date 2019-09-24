#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "DeregistrationType.h"
#include "NASKeySetIdentifier.h"
#include "_5GSMobileIdentity.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define DEREGISTRATION_REQUEST_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		DEREGISTRATION_TYPE_MINIMUM_LENGTH + \
		NAS_KEY_SET_IDENTIFIER_MINIMUM_LENGTH + \
		_5GS_MOBILE_IDENTITY_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define DEREGISTRATION_REQUEST_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		DEREGISTRATION_TYPE_MAXIMUM_LENGTH + \
		NAS_KEY_SET_IDENTIFIER_MAXIMUM_LENGTH + \
		_5GS_MOBILE_IDENTITY_MAXIMUM_LENGTH + \
0)

typedef struct deregistration_request_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
	DeregistrationType deregistrationtype;
	NASKeySetIdentifier naskeysetidentifier;
	_5GSMobileIdentity _5gsmobileidentity;
}deregistration_request_msg;


int decode_deregistration_request(deregistration_request_msg *deregistrationrequest, uint8_t *buffer, uint32_t len);
int encode_deregistration_request(deregistration_request_msg *deregistrationrequest, uint8_t *buffer, uint32_t len);
