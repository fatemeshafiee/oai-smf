#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "PDUSessionStatus.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define NOTIFICATION_RESPONSE_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		PDU_SESSION_STATUS_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define NOTIFICATION_RESPONSE_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		PDU_SESSION_STATUS_MAXIMUM_LENGTH + \
0)

typedef struct notification_response_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
	PDUSessionStatus pdusessionstatus;
}notification_response_msg;


int decode_notification_response(notification_response_msg *notificationresponse, uint8_t *buffer, uint32_t len);
int encode_notification_response(notification_response_msg *notificationresponse, uint8_t *buffer, uint32_t len);
