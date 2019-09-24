#include <stdint.h>
#include "bstrlib.h"

#define LADN_INFORMATION_MINIMUM_LENGTH 3
#define LADN_INFORMATION_MAXIMUM_LENGTH 1715

typedef bstring LADNInformation;

int encode_ladn_information ( LADNInformation ladninformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_ladn_information ( LADNInformation * ladninformation, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

