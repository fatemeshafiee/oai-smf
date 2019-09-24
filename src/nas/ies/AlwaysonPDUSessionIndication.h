#include <stdint.h>
#include "bstrlib.h"

#define ALWAYSON_PDU_SESSION_INDICATION_MINIMUM_LENGTH 1
#define ALWAYSON_PDU_SESSION_INDICATION_MAXIMUM_LENGTH 1

typedef bstring AlwaysonPDUSessionIndication;

int encode_alwayson_pdu_session_indication ( AlwaysonPDUSessionIndication alwaysonpdusessionindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_alwayson_pdu_session_indication ( AlwaysonPDUSessionIndication * alwaysonpdusessionindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

