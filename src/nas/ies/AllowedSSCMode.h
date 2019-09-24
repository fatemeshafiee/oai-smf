#include <stdint.h>
#include "bstrlib.h"

#define ALLOWED_SSC_MODE_MINIMUM_LENGTH 1
#define ALLOWED_SSC_MODE_MAXIMUM_LENGTH 1

typedef bstring AllowedSSCMode;

int encode_allowed_ssc_mode ( AllowedSSCMode allowedsscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_allowed_ssc_mode ( AllowedSSCMode * allowedsscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

