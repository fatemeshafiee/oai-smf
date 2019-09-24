#include <stdint.h>
#include "bstrlib.h"

#define PDU_SESSION_STATUS_MINIMUM_LENGTH 4
#define PDU_SESSION_STATUS_MAXIMUM_LENGTH 34

typedef uint16_t PDUSessionStatus;

int encode_pdu_session_status ( PDUSessionStatus pdusessionstatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_pdu_session_status ( PDUSessionStatus * pdusessionstatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

