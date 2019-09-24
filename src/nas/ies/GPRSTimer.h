#include <stdint.h>
#include "bstrlib.h"

#define GPRS_TIMER_MINIMUM_LENGTH 2
#define GPRS_TIMER_MAXIMUM_LENGTH 2

typedef bstring GPRSTimer;

int encode_gprs_timer ( GPRSTimer gprstimer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_gprs_timer ( GPRSTimer * gprstimer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

