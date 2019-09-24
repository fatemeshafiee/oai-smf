#include <stdint.h>
#include "bstrlib.h"

#define MESSAGE_AUTHENTICATION_CODE_MINIMUM_LENGTH 4
#define MESSAGE_AUTHENTICATION_CODE_MAXIMUM_LENGTH 4

typedef bstring MessageAuthenticationCode;

int encode_message_authentication_code ( MessageAuthenticationCode messageauthenticationcode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_message_authentication_code ( MessageAuthenticationCode * messageauthenticationcode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

