#include <stdint.h>
#include "bstrlib.h"

#define ADDITIONAL_INFORMATION_MINIMUM_LENGTH 3
#define ADDITIONAL_INFORMATION_MAXIMUM_LENGTH 9999

typedef bstring AdditionalInformation;

int encode_additional_information ( AdditionalInformation additionalinformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_additional_information ( AdditionalInformation * additionalinformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

