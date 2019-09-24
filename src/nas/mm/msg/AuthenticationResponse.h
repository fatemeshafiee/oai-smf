#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "AuthenticationResponseParameter.h"
#include "EAPMessage.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define AUTHENTICATION_RESPONSE_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		AUTHENTICATION_RESPONSE_PARAMETER_MINIMUM_LENGTH + \
		EAP_MESSAGE_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define AUTHENTICATION_RESPONSE_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		AUTHENTICATION_RESPONSE_PARAMETER_MAXIMUM_LENGTH + \
		EAP_MESSAGE_MAXIMUM_LENGTH + \
0)

#define AUTHENTICATION_RESPONSE_AUTHENTICATION_RESPONSE_PARAMETER_IEI 0x2d
#define AUTHENTICATION_RESPONSE_EAP_MESSAGE_IEI 0x78

#define AUTHENTICATION_RESPONSE_AUTNENTICATION_RESPONSE_PARAMETER_PRESENT (1<<0)
#define AUTHENTICATION_RESPONSE_EAP_MESSAGE_PRESENT (1<<1)

typedef struct authentication_response_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
    uint8_t presence;
	AuthenticationResponseParameter authenticationresponseparameter;
	EAPMessage eapmessage;
}authentication_response_msg;


int decode_authentication_response(authentication_response_msg *authenticationresponse, uint8_t *buffer, uint32_t len);
int encode_authentication_response(authentication_response_msg *authenticationresponse, uint8_t *buffer, uint32_t len);
