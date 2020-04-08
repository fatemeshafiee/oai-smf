#ifndef __PDUSessionType_H_
#define __PDUSessionType_H_

#include <stdint.h>
#include "bstrlib.h"

#define _PDU_SESSION_TYPE_MINIMUM_LENGTH 1
#define _PDU_SESSION_TYPE_MAXIMUM_LENGTH 1

typedef struct  {
  uint8_t spare:5;
  uint8_t pdu_session_type_value:3;
} __attribute__((__packed__)) _PDUSessionType;
 

int encode__pdu_session_type ( _PDUSessionType _pdusessiontype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__pdu_session_type ( _PDUSessionType * _pdusessiontype, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
