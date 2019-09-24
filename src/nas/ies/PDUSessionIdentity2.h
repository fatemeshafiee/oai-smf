#include <stdint.h>
#include "bstrlib.h"

#define PDU_SESSION_IDENTITY2_MINIMUM_LENGTH 2
#define PDU_SESSION_IDENTITY2_MAXIMUM_LENGTH 2

typedef bstring PDUSessionIdentity2;

int encode_pdu_session_identity2 ( PDUSessionIdentity2 pdusessionidentity2, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_pdu_session_identity2 ( PDUSessionIdentity2 * pdusessionidentity2, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

