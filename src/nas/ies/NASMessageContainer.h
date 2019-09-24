#include <stdint.h>
#include "bstrlib.h"

#define NAS_MESSAGE_CONTAINER_MINIMUM_LENGTH 4
#define NAS_MESSAGE_CONTAINER_MAXIMUM_LENGTH 65535

typedef bstring NASMessageContainer;

int encode_nas_message_container ( NASMessageContainer nasmessagecontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_nas_message_container ( NASMessageContainer * nasmessagecontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

