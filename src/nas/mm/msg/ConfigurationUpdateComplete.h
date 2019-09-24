#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define CONFIGURATION_UPDATE_COMPLETE_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define CONFIGURATION_UPDATE_COMPLETE_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
0)

typedef struct configuration_update_complete_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
}configuration_update_complete_msg;


int decode_configuration_update_complete(configuration_update_complete_msg *configurationupdatecomplete, uint8_t *buffer, uint32_t len);
int encode_configuration_update_complete(configuration_update_complete_msg *configurationupdatecomplete, uint8_t *buffer, uint32_t len);
