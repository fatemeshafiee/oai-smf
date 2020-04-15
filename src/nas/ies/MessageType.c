#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "MessageType.h"

int encode_message_type(MessageType messagetype, uint8_t iei, uint8_t *buffer,
                        uint32_t len) {
//we don't need this since it's done in encode header ENCODE_U8
  return 0;
}

int decode_message_type(MessageType *messagetype, uint8_t iei, uint8_t *buffer,
                        uint32_t len) {
  //we don't need this since it's done in decode header (DECODE_U8)
  return 0;
}

