#include <stdint.h>
#include "bstrlib.h"

#define MAPPED_EPS_BEARER_CONTEXTS_MINIMUM_LENGTH 7
#define MAPPED_EPS_BEARER_CONTEXTS_MAXIMUM_LENGTH 65538

typedef bstring MappedEPSBearerContexts;

int encode_mapped_eps_bearer_contexts ( MappedEPSBearerContexts mappedepsbearercontexts, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_mapped_eps_bearer_contexts ( MappedEPSBearerContexts * mappedepsbearercontexts, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

