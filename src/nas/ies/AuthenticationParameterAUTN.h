#include <stdint.h>
#include "bstrlib.h"

#define AUTHENTICATION_PARAMETER_AUTN_MINIMUM_LENGTH 18
#define AUTHENTICATION_PARAMETER_AUTN_MAXIMUM_LENGTH 18

typedef bstring AuthenticationParameterAUTN;

int encode_authentication_parameter_autn ( AuthenticationParameterAUTN authenticationparameterautn, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_authentication_parameter_autn ( AuthenticationParameterAUTN * authenticationparameterautn, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

