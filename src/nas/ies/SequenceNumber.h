#include <stdint.h>
#include "bstrlib.h"

#define SEQUENCE_NUMBER_MINIMUM_LENGTH 1
#define SEQUENCE_NUMBER_MAXIMUM_LENGTH 1

typedef bstring SequenceNumber;

int encode_sequence_number ( SequenceNumber sequencenumber, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_sequence_number ( SequenceNumber * sequencenumber, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

