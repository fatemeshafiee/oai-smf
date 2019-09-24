#include <stdint.h>
#include "bstrlib.h"

#define AUTHENTICATION_FAILURE_PARAMETER_MINIMUM_LENGTH 16
#define AUTHENTICATION_FAILURE_PARAMETER_MAXIMUM_LENGTH 16

typedef bstring AuthenticationFailureParameter;

int encode_authentication_failure_parameter ( AuthenticationFailureParameter authenticationfailureparameter, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_authentication_failure_parameter ( AuthenticationFailureParameter * authenticationfailureparameter, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

