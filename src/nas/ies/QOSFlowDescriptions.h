#include <stdint.h>
#include "bstrlib.h"

#define QOS_FLOW_DESCRIPTIONS_MINIMUM_LENGTH 5
#define QOS_FLOW_DESCRIPTIONS_MAXIMUM_LENGTH 65538

typedef bstring QOSFlowDescriptions;

int encode_qos_flow_descriptions ( QOSFlowDescriptions qosflowdescriptions, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_qos_flow_descriptions ( QOSFlowDescriptions * qosflowdescriptions, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

