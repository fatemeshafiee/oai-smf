#include <stdint.h>
#include "bstrlib.h"

#define PDU_SESSION_REACTIVATION_RESULT_MINIMUM_LENGTH 4
#define PDU_SESSION_REACTIVATION_RESULT_MAXIMUM_LENGTH 34

typedef uint16_t PDUSessionReactivationResult;

int encode_pdu_session_reactivation_result ( PDUSessionReactivationResult pdusessionreactivationresult, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_pdu_session_reactivation_result ( PDUSessionReactivationResult * pdusessionreactivationresult, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

