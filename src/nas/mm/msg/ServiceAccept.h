#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "PDUSessionStatus.h"
#include "PDUSessionReactivationResult.h"
#include "PDUSessionReactivationResultErrorCause.h"
#include "EAPMessage.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define SERVICE_ACCEPT_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		PDU_SESSION_STATUS_MINIMUM_LENGTH + \
		PDU_SESSION_REACTIVATION_RESULT_MINIMUM_LENGTH + \
		PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_MINIMUM_LENGTH + \
		EAP_MESSAGE_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define SERVICE_ACCEPT_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		PDU_SESSION_STATUS_MAXIMUM_LENGTH + \
		PDU_SESSION_REACTIVATION_RESULT_MAXIMUM_LENGTH + \
		PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_MAXIMUM_LENGTH + \
		EAP_MESSAGE_MAXIMUM_LENGTH + \
0)

typedef struct service_accept_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
	PDUSessionStatus pdusessionstatus;
	PDUSessionReactivationResult pdusessionreactivationresult;
	PDUSessionReactivationResultErrorCause pdusessionreactivationresulterrorcause;
	EAPMessage eapmessage;
}service_accept_msg;


int decode_service_accept(service_accept_msg *serviceaccept, uint8_t *buffer, uint32_t len);
int encode_service_accept(service_accept_msg *serviceaccept, uint8_t *buffer, uint32_t len);
