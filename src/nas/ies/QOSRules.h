#include <stdint.h>
#include "bstrlib.h"

#define QOS_RULES_MINIMUM_LENGTH 7
#define QOS_RULES_MAXIMUM_LENGTH 65538

typedef bstring QOSRules;

int encode_qos_rules ( QOSRules qosrules, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_qos_rules ( QOSRules * qosrules, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

