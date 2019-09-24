#include <stdint.h>
#include "bstrlib.h"

#define REJECTED_NSSAI_MINIMUM_LENGTH 4
#define REJECTED_NSSAI_MAXIMUM_LENGTH 42

typedef bstring RejectedNSSAI;

int encode_rejected_nssai ( RejectedNSSAI rejectednssai, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_rejected_nssai ( RejectedNSSAI * rejectednssai, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

