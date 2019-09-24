#include <stdint.h>
#include "bstrlib.h"

#define SESSION_AMBR_MINIMUM_LENGTH 8
#define SESSION_AMBR_MAXIMUM_LENGTH 8

typedef bstring SessionAMBR;

int encode_session_ambr ( SessionAMBR sessionambr, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_session_ambr ( SessionAMBR * sessionambr, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

