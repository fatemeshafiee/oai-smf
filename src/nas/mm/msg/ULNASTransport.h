#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageType.h"
#include "PayloadContainerType.h"
#include "PayloadContainer.h"
#include "PDUSessionIdentity2.h"
#include "RequestTypeNas.h"
#include "SNSSAI.h"
#include "DNN.h"
#include "AdditionalInformation.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define ULNAS_TRANSPORT_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		PAYLOAD_CONTAINER_TYPE_MINIMUM_LENGTH + \
		PAYLOAD_CONTAINER_MINIMUM_LENGTH + \
		PDU_SESSION_IDENTITY2_MINIMUM_LENGTH + \
		REQUEST_TYPE_MINIMUM_LENGTH + \
		SNSSAI_MINIMUM_LENGTH + \
		DNN_MINIMUM_LENGTH + \
		ADDITIONAL_INFORMATION_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define ULNAS_TRANSPORT_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		PAYLOAD_CONTAINER_TYPE_MAXIMUM_LENGTH + \
		PAYLOAD_CONTAINER_MAXIMUM_LENGTH + \
		PDU_SESSION_IDENTITY2_MAXIMUM_LENGTH + \
		REQUEST_TYPE_MAXIMUM_LENGTH + \
		SNSSAI_MAXIMUM_LENGTH + \
		DNN_MAXIMUM_LENGTH + \
		ADDITIONAL_INFORMATION_MAXIMUM_LENGTH + \
0)

typedef struct ulnas_transport_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageType messagetype;
	PayloadContainerType payloadcontainertype;
	PayloadContainer payloadcontainer;
	PDUSessionIdentity2 pdusessionidentity2;
	RequestType requesttype;
	SNSSAI snssai;
	DNN dnn;
	AdditionalInformation additionalinformation;
}ulnas_transport_msg;


int decode_ulnas_transport(ulnas_transport_msg *ulnastransport, uint8_t *buffer, uint32_t len);
int encode_ulnas_transport(ulnas_transport_msg *ulnastransport, uint8_t *buffer, uint32_t len);
