#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "SecurityHeaderType.h"
#include "MessageAuthenticationCode.h"
#include "SequenceNumber.h"
#include "Plain5GSNASMessage.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define SECURITY_PROTECTED5_GSNAS_MESSAGE_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MINIMUM_LENGTH + \
		MESSAGE_AUTHENTICATION_CODE_MINIMUM_LENGTH + \
		SEQUENCE_NUMBER_MINIMUM_LENGTH + \
		PLAIN_5GSNAS_MESSAGE_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define SECURITY_PROTECTED5_GSNAS_MESSAGE_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		SECURITY_HEADER_TYPE_MAXIMUM_LENGTH + \
		MESSAGE_AUTHENTICATION_CODE_MAXIMUM_LENGTH + \
		SEQUENCE_NUMBER_MAXIMUM_LENGTH + \
		PLAIN_5GSNAS_MESSAGE_MAXIMUM_LENGTH + \
0)

typedef struct security_protected5_gsnas_message_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	SecurityHeaderType securityheadertype;
	MessageAuthenticationCode messageauthenticationcode;
	SequenceNumber sequencenumber;
	Plain5GSNASMessage plain5gsnasmessage;
}security_protected5_gsnas_message_msg;


int decode_security_protected5_gsnas_message(security_protected5_gsnas_message_msg *securityprotected5gsnasmessage, uint8_t *buffer, uint32_t len);
int encode_security_protected5_gsnas_message(security_protected5_gsnas_message_msg *securityprotected5gsnasmessage, uint8_t *buffer, uint32_t len);
