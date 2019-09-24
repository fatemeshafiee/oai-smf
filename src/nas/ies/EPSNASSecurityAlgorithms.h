#include <stdint.h>
#include "bstrlib.h"

#define EPSNAS_SECURITY_ALGORITHMS_MINIMUM_LENGTH 2
#define EPSNAS_SECURITY_ALGORITHMS_MAXIMUM_LENGTH 2

#define NAS_SECURITY_ALGORITHMS_EEA0 0b000
#define NAS_SECURITY_ALGORITHMS_EEA1 0b001
#define NAS_SECURITY_ALGORITHMS_EEA2 0b010
#define NAS_SECURITY_ALGORITHMS_EEA3 0b011
#define NAS_SECURITY_ALGORITHMS_EEA4 0b100
#define NAS_SECURITY_ALGORITHMS_EEA5 0b101
#define NAS_SECURITY_ALGORITHMS_EEA6 0b110
#define NAS_SECURITY_ALGORITHMS_EEA7 0b111


#define NAS_SECURITY_ALGORITHMS_EIA0 0b000
#define NAS_SECURITY_ALGORITHMS_EIA1 0b001
#define NAS_SECURITY_ALGORITHMS_EIA2 0b010
#define NAS_SECURITY_ALGORITHMS_EIA3 0b011
#define NAS_SECURITY_ALGORITHMS_EIA4 0b100
#define NAS_SECURITY_ALGORITHMS_EIA5 0b101
#define NAS_SECURITY_ALGORITHMS_EIA6 0b110
#define NAS_SECURITY_ALGORITHMS_EIA7 0b111

typedef struct{
  uint8_t typeOfCipheringAlgoithm:3;
  uint8_t typeOfIntegrityProtectionAlgoithm:3;
} EPSNASSecurityAlgorithms;

int encode_epsnas_security_algorithms ( EPSNASSecurityAlgorithms epsnassecurityalgorithms, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_epsnas_security_algorithms ( EPSNASSecurityAlgorithms * epsnassecurityalgorithms, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

