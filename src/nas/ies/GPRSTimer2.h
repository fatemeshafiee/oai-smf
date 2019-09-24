#include <stdint.h>
#include "bstrlib.h"

#define GPRS_TIMER2_MINIMUM_LENGTH 3
#define GPRS_TIMER2_MAXIMUM_LENGTH 3

typedef uint8_t GPRSTimer2;

int encode_gprs_timer2 ( GPRSTimer2 gprstimer2, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_gprs_timer2 ( GPRSTimer2 * gprstimer2, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

