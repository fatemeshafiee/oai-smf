#include <stdint.h>
#include "bstrlib.h"

#define PDU_ADDRESS_MINIMUM_LENGTH 7
#define PDU_ADDRESS_MAXIMUM_LENGTH 15

typedef bstring PDUAddress;

int encode_pdu_address ( PDUAddress pduaddress, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_pdu_address ( PDUAddress * pduaddress, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

