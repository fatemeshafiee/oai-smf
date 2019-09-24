#include <stdint.h>
#include "bstrlib.h"

#define ALWAYSON_PDU_SESSION_REQUESTED_MINIMUM_LENGTH 1
#define ALWAYSON_PDU_SESSION_REQUESTED_MAXIMUM_LENGTH 1

typedef bstring AlwaysonPDUSessionRequested;

int encode_alwayson_pdu_session_requested ( AlwaysonPDUSessionRequested alwaysonpdusessionrequested, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_alwayson_pdu_session_requested ( AlwaysonPDUSessionRequested * alwaysonpdusessionrequested, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

