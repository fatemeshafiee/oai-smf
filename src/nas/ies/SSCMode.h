#include <stdint.h>
#include "bstrlib.h"

#define SSC_MODE_MINIMUM_LENGTH 1
#define SSC_MODE_MAXIMUM_LENGTH 1

typedef bstring SSCMode;

int encode_ssc_mode ( SSCMode sscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_ssc_mode ( SSCMode * sscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

