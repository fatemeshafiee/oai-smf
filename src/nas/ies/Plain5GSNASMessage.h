#include <stdint.h>
#include "bstrlib.h"

#define PLAIN_5GSNAS_MESSAGE_MINIMUM_LENGTH 0
#define PLAIN_5GSNAS_MESSAGE_MAXIMUM_LENGTH 65538

typedef bstring Plain5GSNASMessage;

int encode_plain_5gsnas_message ( Plain5GSNASMessage plain5gsnasmessage, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_plain_5gsnas_message ( Plain5GSNASMessage * plain5gsnasmessage, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

