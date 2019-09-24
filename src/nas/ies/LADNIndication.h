#include <stdint.h>
#include "bstrlib.h"

#define LADN_INDICATION_MINIMUM_LENGTH 3
#define LADN_INDICATION_MAXIMUM_LENGTH 811

typedef bstring LADNIndication;

int encode_ladn_indication ( LADNIndication ladnindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_ladn_indication ( LADNIndication * ladnindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

