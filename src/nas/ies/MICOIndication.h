#ifndef _MICO_INDICATION_H_
#define _MICO_INDICATION_H_

#include <stdint.h>
#include "bstrlib.h"
#include <stdbool.h>

#define MICO_INDICATION_MINIMUM_LENGTH 1
#define MICO_INDICATION_MAXIMUM_LENGTH 1

typedef struct{
  bool raai;//registration area allocation indication
} MICOIndication;

int encode_mico_indication ( MICOIndication micoindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_mico_indication ( MICOIndication * micoindication, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
