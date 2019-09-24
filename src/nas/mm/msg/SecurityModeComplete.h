#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "_5GSMobileIdentity.h"
#include "NASMessageContainer.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define SECURITY_MODE_COMPLETE_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		_5GS_MOBILE_IDENTITY_MINIMUM_LENGTH + \
		NAS_MESSAGE_CONTAINER_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define SECURITY_MODE_COMPLETE_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		_5GS_MOBILE_IDENTITY_MAXIMUM_LENGTH + \
		NAS_MESSAGE_CONTAINER_MAXIMUM_LENGTH + \
0)

#define SECURITY_MODE_COMPLETE_5G_MOBILE_IDENTITY_IEI 0x77
#define SECURITY_MODE_COMPLETE_5G_MOBILE_IDENTITY_PRESENT (1<<0)
#define SECURITY_MODE_COMPLETE_NAS_MESSAGE_CONTAINER_IEI 0x71
#define SECURITY_MODE_COMPLETE_NAS_MESSAGE_CONTAINER_PRESENT (1<<1)


typedef struct security_mode_complete_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
        uint8_t presence;
	//_5GSMobileIdentity _5gsmobileidentity;
	NASMessageContainer nasmessagecontainer;
}security_mode_complete_msg;


int decode_security_mode_complete(security_mode_complete_msg *securitymodecomplete, uint8_t *buffer, uint32_t len);
int encode_security_mode_complete(security_mode_complete_msg *securitymodecomplete, uint8_t *buffer, uint32_t len);
