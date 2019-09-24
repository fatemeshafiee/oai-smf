#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "EAPMessage.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define AUTHENTICATION_REJECT_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
                EAP_MESSAGE_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define AUTHENTICATION_REJECT_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
                EAP_MESSAGE_MAXIMUM_LENGTH +\
0)

#define AUTHENTICATION_REJECT_EAP_MESSAGE_IEI 0x78
#define AUTHENTICATION_REJECT_EAP_MESSAGE_PRESENT (1<<0)

typedef struct authentication_reject_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
    uint8_t presence;
    EAPMessage eapmessage;
}authentication_reject_msg;


int decode_authentication_reject(authentication_reject_msg *authenticationreject, uint8_t *buffer, uint32_t len);
int encode_authentication_reject(authentication_reject_msg *authenticationreject, uint8_t *buffer, uint32_t len);
