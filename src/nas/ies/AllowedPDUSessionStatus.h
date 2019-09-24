#include <stdint.h>
#include "bstrlib.h"

#define ALLOWED_PDU_SESSION_STATUS_MINIMUM_LENGTH 4
#define ALLOWED_PDU_SESSION_STATUS_MAXIMUM_LENGTH 34

typedef uint8_t AllowedPDUSessionStatus;

int encode_allowed_pdu_session_status ( AllowedPDUSessionStatus allowedpdusessionstatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_allowed_pdu_session_status ( AllowedPDUSessionStatus * allowedpdusessionstatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

