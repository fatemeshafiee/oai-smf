#include <stdint.h>
#include "bstrlib.h"

#define AUTHENTICATION_RESPONSE_PARAMETER_MINIMUM_LENGTH 6
#define AUTHENTICATION_RESPONSE_PARAMETER_MAXIMUM_LENGTH 18

typedef bstring AuthenticationResponseParameter;

int encode_authentication_response_parameter ( AuthenticationResponseParameter authenticationresponseparameter, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_authentication_response_parameter ( AuthenticationResponseParameter * authenticationresponseparameter, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

