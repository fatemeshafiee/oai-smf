#include <stdint.h>
#include "bstrlib.h"

#define PDU_SESSION_IDENTITY_MINIMUM_LENGTH 1
#define PDU_SESSION_IDENTITY_MAXIMUM_LENGTH 1

typedef uint8_t PDUSessionIdentity;

int encode_pdu_session_identity ( PDUSessionIdentity pdusessionidentity, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_pdu_session_identity ( PDUSessionIdentity * pdusessionidentity, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

