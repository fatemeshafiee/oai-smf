#include <stdint.h>
#include "bstrlib.h"

#define DEREGISTRATION_TYPE_MINIMUM_LENGTH 1
#define DEREGISTRATION_TYPE_MAXIMUM_LENGTH 1

typedef bstring DeregistrationType;

int encode_deregistration_type ( DeregistrationType deregistrationtype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_deregistration_type ( DeregistrationType * deregistrationtype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

