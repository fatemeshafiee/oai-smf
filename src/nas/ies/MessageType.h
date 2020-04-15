#include <stdint.h>
#include "bstrlib.h"

#define MESSAGE_TYPE_MINIMUM_LENGTH 1
#define MESSAGE_TYPE_MAXIMUM_LENGTH 1

typedef uint8_t MessageType;

int encode_message_type(MessageType messagetype, uint8_t iei, uint8_t *buffer,
                        uint32_t len);
int decode_message_type(MessageType *messagetype, uint8_t iei, uint8_t *buffer,
                        uint32_t len);
