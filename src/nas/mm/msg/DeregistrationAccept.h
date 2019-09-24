#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define DEREGISTRATION_ACCEPT_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define DEREGISTRATION_ACCEPT_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
0)

typedef struct deregistration_accept_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
}deregistration_accept_msg;


int decode_deregistration_accept(deregistration_accept_msg *deregistrationaccept, uint8_t *buffer, uint32_t len);
int encode_deregistration_accept(deregistration_accept_msg *deregistrationaccept, uint8_t *buffer, uint32_t len);
