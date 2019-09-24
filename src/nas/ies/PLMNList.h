#include <stdint.h>
#include "bstrlib.h"

#define PLMN_LIST_MINIMUM_LENGTH 5
#define PLMN_LIST_MAXIMUM_LENGTH 47

typedef struct {
  uint16_t mcc;
  uint16_t mnc;
}PLMN;
typedef PLMN  PLMNList[15];

int encode_plmn_list ( PLMNList plmnlist, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_plmn_list ( PLMNList plmnlist, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

