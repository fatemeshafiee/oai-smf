#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "_AccessType.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define NOTIFICATION_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		_ACCESS_TYPE_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define NOTIFICATION_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		_ACCESS_TYPE_MAXIMUM_LENGTH + \
0)

typedef struct notification_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
	_AccessType _accesstype;
}notification_msg;


int decode_notification(notification_msg *notification, uint8_t *buffer, uint32_t len);
int encode_notification(notification_msg *notification, uint8_t *buffer, uint32_t len);
