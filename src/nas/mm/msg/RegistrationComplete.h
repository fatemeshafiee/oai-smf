#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "SORTransparentContainer.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define REGISTRATION_COMPLETE_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		SOR_TRANSPARENT_CONTAINER_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define REGISTRATION_COMPLETE_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		SOR_TRANSPARENT_CONTAINER_MAXIMUM_LENGTH + \
0)

typedef struct registration_complete_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
	SORTransparentContainer sortransparentcontainer;
}registration_complete_msg;


int decode_registration_complete(registration_complete_msg *registrationcomplete, uint8_t *buffer, uint32_t len);
int encode_registration_complete(registration_complete_msg *registrationcomplete, uint8_t *buffer, uint32_t len);
