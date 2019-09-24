#ifndef _PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_H_
#define _PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_H_

#include <stdint.h>
#include "bstrlib.h"

#define PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_MINIMUM_LENGTH 5
#define PDU_SESSION_REACTIVATION_RESULT_ERROR_CAUSE_MAXIMUM_LENGTH 515

struct PduSessionID_CauseValue{
  uint8_t pduSessionID;
  uint8_t causeValue;
  struct PduSessionID_CauseValue * next;
};

typedef struct {
  uint16_t size;
  struct PduSessionID_CauseValue * element;
}PDUSessionReactivationResultErrorCause;

int encode_pdu_session_reactivation_result_error_cause ( PDUSessionReactivationResultErrorCause pdusessionreactivationresulterrorcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_pdu_session_reactivation_result_error_cause ( PDUSessionReactivationResultErrorCause * pdusessionreactivationresulterrorcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
#endif
