#include <stdint.h>
#include "bstrlib.h"

#define SMS_INDICATION_MINIMUM_LENGTH 1
#define SMS_INDICATION_MAXIMUM_LENGTH 1

typedef bstring SMSIndication;

int encode_sms_indication ( SMSIndication smsindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_sms_indication ( SMSIndication * smsindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

