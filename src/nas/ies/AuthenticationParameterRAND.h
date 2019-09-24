#include <stdint.h>
#include "bstrlib.h"

#define AUTHENTICATION_PARAMETER_RAND_MINIMUM_LENGTH 17
#define AUTHENTICATION_PARAMETER_RAND_MAXIMUM_LENGTH 17

typedef bstring AuthenticationParameterRAND;

int encode_authentication_parameter_rand ( AuthenticationParameterRAND authenticationparameterrand, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_authentication_parameter_rand ( AuthenticationParameterRAND * authenticationparameterrand, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

