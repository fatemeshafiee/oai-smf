#ifndef FILE_3GPP_24_501_H_SEEN
#define FILE_3GPP_24_501_H_SEEN
#ifdef __cplusplus
extern "C" {
#endif

// 9.3.1 Security header type
#define SECURITY_HEADER_TYPE_NOT_PROTECTED                    0b0000
#define SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED              0b0001
#define SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED     0b0010
#define SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_NEW          0b0011
#define SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED_NEW 0b0100


/*
 *  This file contains NAS header bits format
 *  Refer TS24.007 TS24.501
 *  Auther: Puzyu Dukl
 *  Time:
 *  Email: hr@
 */

/*Extended Protocol Discriminator (EPD)*/

//8 bits
//big endian
#define _5GSSessionManagementMessages       0b00101110
#define _5GSMobilityManagementMessages      0b01111110


/* Security Header Type*/
//4 bits
#define Plain5GSNASMessage                                          0b0000
#define IntegrityProtected                                          0b0001
#define IntegrityProtectedAndCiphered                               0b0010
#define IntegrityProtectedWithNew5GNASSecurityContext               0b0011
#define IntegrityProtectedAndCipheredWithNew5GNASSecurityContext    0b0100

#define SpareHalfOctet                                              0b0000 /*填充用*/

/* Message Type for Mobility Management */

// 0b01******
/* 5GS Mobility Management Messages */

#define REGISTRATION_REQUEST                    0b01000001
#define REGISTRATION_ACCEPT                     0b01000010
#define REGISTRATION_COMPLETE                   0b01000011
#define REGISTRATION_REJECT                     0b01000100
#define DEREGISTRATION_REQUEST_UE_ORIGINATING   0b01000101
#define DEREGISTRATION_ACCEPT_UE_ORIGINATING    0b01000110
#define DEREGISTRATION_REQUEST_UE_TERMINATED    0b01000111
#define DEREGISTRATION_ACCEPT_UE_TERMINATED     0b01001000

#define SERVICE_REQUEST                         0b01001100
#define SERVICE_REJECT                          0b01001101
#define SERVICE_ACCEPT                          0b01001110

#define CONFIGURATION_UPDATE_COMMAND            0b01010100
#define CONFIGURATION_UPDATE_COMPLETE           0b01010101
#define AUTHENTICATION_REQUEST                  0b01010110
#define AUTHENTICATION_RESPONSE                 0b01010111
#define AUTHENTICATION_REJECT                   0b01011000
#define AUTHENTICATION_FAILURE                  0b01011001 
#define AUTHENTICATION_RESULT                   0b01011010
#define IDENTITY_REQUEST                        0b01011011
#define IDENTITY_RESPONSE                       0b01011100
#define SECURITY_MODE_COMMAND                   0b01011101
#define SECURITY_MODE_COMPLETE                  0b01011110
#define SECURITY_MODE_REJECT                    0b01011111

#define _5GMM_STATUS                            0b01100100
#define NOTIFICATION                            0b01100101
#define NOTIFICATION_RESPONSE                   0b01100110
#define ULNAS_TRANSPORT                         0b01100111
#define DLNAS_TRANSPORT                         0b01101000


/* Message Type for Session Management */

//0b11******
//5GS Session Management Messages

#define PDU_SESSION_ESTABLISHMENT_REQUEST       0b11000001
#define PDU_SESSION_ESTABLISHMENT_ACCPET        0b11000010
#define PDU_SESSION_ESTABLISHMENT_REJECT        0b11000011

#define PDU_SESSION_AUTHENTICATION_COMMAND      0b11000101
#define PDU_SESSION_AUTHENTICATION_COMPLETE     0b11000110
#define PDU_SESSION_AUTHENTICATION_RESULT       0b11000111

#define PDU_SESSION_MODIFICATION_REQUEST        0b11001001
#define PDU_SESSION_MODIFICATION_REJECT         0b11001010
#define PDU_SESSION_MODIFICATION_COMMAND        0b11001011
#define PDU_SESSION_MODIFICATION_COMPLETE       0b11001100
#define PDU_SESSION_MODIFICATION_COMMANDREJECT  0b11001101

#define PDU_SESSION_RELEASE_REQUEST             0b11010001
#define PDU_SESSION_RELEASE_REJECT              0b11010010
#define PDU_SESSION_RELEASE_COMMAND             0b11010011
#define PDU_SESSION_RELEASE_COMPLETE            0b11010100

#define _5GSM_STATUS                             0b11010110



// 9.11.3.47 Request type
typedef uint8_t request_type_t;

enum request_type_e {
	INITIAL_REQUEST = 1,
	EXISTING_PDU_SESSION = 2,
	INITIAL_EMERGENCY_REQUEST = 3,
	EXISTING_EMERGENCY_PDU_SESSION = 4,
	MODIFICATION_REQUEST = 5,
	MA_PDU_REQUEST = 6,
	REQUEST_TYPE_RESERVED = 7
};


/*
 * Message Authentication Code
 * 木得定义
 * The message authentication code (MAC) information element contains
 * the integrity protection information for the message.
 */

/*---------------------------------------------------------------------------------------------*/





/*
 * Plain 5GS NAS Message
 *
 * This IE includes a complete plain 5GS NAS message as specified
 * in subclauses 8.2 and 8.3. The SECURITY PROTECTED 5GS NAS MESSAGE message
 * (see subclause 8.2.28) is not plain 5GS NAS messages and shall not be included in this IE.
 */

/*---------------------------------------------------------------------------------------------*/





/*
 *
 * Sequence Number
 *
 * This IE includes the NAS message sequence number (SN)
 * which consists of the eight least significant bits of
 * the NAS COUNT for a SECURITY PROTECTED 5GS NAS MESSAGE message.
 * The usage of SN is specified in subclause 4.4.3.
 *
 */


/*---------------------------------------------------------------------------------------------*/



/*
 * Other information elements
 *
 */


/*---------------------------------------------------------------------------------------------*/


/*
 * 5GMM cause types
*/

#define IIEGAL_UE                         	0b00000011 
#define PEI_NOT_ACCEPTED                        0b00000101
#define IIEGAL_ME                               0b00000110
#define FGS_SERVICES_NOT_ALLOWED                0b00000111
#define IMPLICITLY_DE_REGISTERED                0b00001010
#define PLMN_NOT_ALLOWED                        0b00001011
#define TRACKING_AREA_NOT_ALLOWED               0b00001100
#define ROAMING_NOT_ALLOWED_IN_THIS_TA          0b00001101


/*********************************************************************************************/
/*
*  5GS mobile identity information element
*  Type of Identity*/
#define NO_IDENTITY 0b000
#define SUCI        0b001
//#define _5G_GUTI    0b110
#define IMEI        0b011
#define _5G_S_TMSI  0b100
#define IMEISVI     0b101

#define EVEN_IENTITY 0
#define ODD_IDENTITY 1

#ifdef __cplusplus
}

static const std::vector<std::string> request_type_e2str = {
		"ERROR",
		"INITIAL REQUEST",
		"EXISTING_PDU_SESSION",
		"INITIAL_EMERGENCY_REQUEST",
		"EXISTING_EMERGENCY_PDU_SESSION",
		"MODIFICATION_REQUEST",
		"MA_PDU_REQUEST",
		"RESERVED"
};

#endif

#endif
