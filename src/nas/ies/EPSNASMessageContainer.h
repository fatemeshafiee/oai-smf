#include <stdint.h>
#include "bstrlib.h"

#define EPSNAS_MESSAGE_CONTAINER_MINIMUM_LENGTH 3
#define EPSNAS_MESSAGE_CONTAINER_MAXIMUM_LENGTH 65500

typedef bstring EPSNASMessageContainer;

int encode_epsnas_message_container ( EPSNASMessageContainer epsnasmessagecontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_epsnas_message_container ( EPSNASMessageContainer * epsnasmessagecontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

