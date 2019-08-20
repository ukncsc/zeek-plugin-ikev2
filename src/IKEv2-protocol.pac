%include consts.pac

#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       IKE SA Initiator's SPI                  |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       IKE SA Responder's SPI                  |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          Message ID                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Length                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# 				 			IKE Header Format
type IKEv2_PDU(is_orig: bool) = record {
	SAi: bytestring &length=8;
	SAr: bytestring &length=8;
	next_payload: uint8;
	version: uint8;
	exchange_type: uint8;
	flags: uint8;
	message_id: uint32;
	length: uint32;
	data: IKEv2_DATA(this);
} &byteorder=bigendian;

# Flags (1 octet) - Indicates specific options that are set for the
#      message.  Presence of options is indicated by the appropriate bit
#      in the flags field being set.  The bits are as follows:
#        +-+-+-+-+-+-+-+-+
#        |X|X|R|V|I|X|X|X|
#        +-+-+-+-+-+-+-+-+
#      In the description below, a bit being ’set’ means its value is
#      ’1’, while ’cleared’ means its value is ’0’.  ’X’ bits MUST be
#      cleared when sending and MUST be ignored on receipt.
#
type IKEv2_flags = record {
	flags: uint8;
} &let {
	must_ignore_8	: bool = (flags & 0x80) > 0;
	must_ignore_7 	: bool = (flags & 0x40) > 0;
	response		: bool = (flags & 0x20) > 0;
	version			: bool = (flags & 0x01) > 0;
	initiator		: bool = (flags & 0x08) > 0;
	must_ignore_3	: bool = (flags & 0x04) > 0;
	must_ignore_2	: bool = (flags & 0x02) > 0;
	must_ignore_1	: bool = (flags & 0x01) > 0;
};

type IKEv2_DATA(pdu: IKEv2_PDU) = record {
	exchange_type: case pdu.exchange_type of {
		IKE_SA_INIT		-> sa_init	: IKEv2_SA_INIT(pdu);
		# IKE_AUTH		-> auth	: IKEv2_AUTH(pdu);
		# INFORMATIONAL	-> informational : IKEv2_INFORMATIONAL; 
		default 		-> raw_data	: bytestring &restofdata;
	};
} &byteorder=bigendian;

type IKEv2_SA_INIT(pdu: IKEv2_PDU) = record {
	payloads: IKEv2_PAYLOAD(pdu)[] &until($element.last) &requires(set_next_payload);
} &let {
	# Set first payload from pdu next payload field
	set_next_payload: bool	= $context.connection.set_next_payload(pdu.next_payload);
} &byteorder=bigendian

type IKEv2_PAYLOAD(pdu: IKEv2_PDU) = record {
	payload_hdr: IKEv2_PAYLOAD_HDR;
	payload: case $context.connection.get_next_payload() of {
		SA -> sa_payload: IKEv2_SA_PAYLOAD(this);
		KE -> key_exchange_payload: IKEv2_KEY_EXCHANGE_PAYLOAD(pdu, this);
		CERTREQ -> certificate_req_payload: IKEv2_CERT_REQ_PAYLOAD(pdu, this);
		NONCE -> nonce_payload: IKEv2_NONCE_PAYLOAD(pdu, this);
		N -> notify_payload: IKEv2_NOTIFY_PAYLOAD(pdu, this);
		V -> vendor_id_payload: IKEv2_VENDOR_ID_PAYLOAD(pdu, this);
		default -> none: bytestring &restofdata &transient;
	};
} &let {
	set_next_payload :	bool = $context.connection.set_next_payload(payload_hdr.next_payload);
	last: 	bool	= (payload_hdr.next_payload == NO_NEXT_PAYLOAD);
} &byteorder=bigendian &length=payload_hdr.payload_length;

#                      1                   2                   3 
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next Payload  |C|  RESERVED   |         Payload Length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                     Generic Payload Header
type IKEv2_PAYLOAD_HDR() = record {
	next_payload: uint8;
	reserved: uint8;
	payload_length: uint16;
} &let {
	critical: bool = (reserved == 0x08);
} &byteorder=bigendian;

#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next Payload  |C| RESERVED    |         Payload Length        | 
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
# |                                                               | 
# ~                        <Proposals>                            ~                     
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                  Security Association Payload
type IKEv2_SA_PAYLOAD(payload: IKEv2_PAYLOAD) = record {
	proposals: IKEv2_PROPOSAL(payload.pdu)[] &until($element.last);
} &byteorder=bigendian;

#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Last Substruc |    RESERVED   |        Proposal Length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                        SPI (variable)                         ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# ~                         <Transforms>                          ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#					  Proposal Substructure
type IKEv2_PROPOSAL(pdu: IKEv2_PDU) = record {
	proposal_hdr: IKEv2_PAYLOAD_HDR;
	proposal_num: uint8;
	protocol_id: uint8;
	spi_size: uint8;
	num_transforms: uint8;
	spi: bytestring &length = spi_size;
	transforms: IKEv2_TRANSFORM(pdu, this)[num_transforms];
} &let {
	last:	bool	= (proposal_hdr.next_payload == NO_NEXT_PAYLOAD);
} &byteorder=bigendian;

#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Last Substruc |    RESERVED   |        Transform Length       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Transform Type |    RESERVED   |          Transform ID         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# ~                  Transform Attributes                         ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                   Transform Substructure
type IKEv2_TRANSFORM(pdu: IKEv2_PDU, proposal: IKEv2_PROPOSAL) = record {
	transform_hdr: IKEv2_PAYLOAD_HDR;
	transform_type: uint8;
	reserved: uint8;
	transform_id: uint16;
	# There are probably data attributes present if payload_length is above 8
	_data_attributes: bytestring &length = transform_hdr.payload_length - 8;
} &let {
	data_attributes: IKEv2_DATA_ATTRIBUTE withinput _data_attributes &if(transform_hdr.payload_length > 8);
	last:	bool	= (transform_hdr.next_payload == NO_NEXT_PAYLOAD);
} &byteorder=bigendian &length=transform_hdr.payload_length;

#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |A|       Attribute Type        |    AF=0  Attribute Length     |
# |F|                             |    AF=1  Attribute Value      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                   AF=0  Attribute Value                       |
# |                   AF=1  Not Transmitted                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                         Data Attributes
# The only currently defined attribute type (Key Length) is fixed
#   length; the variable-length encoding specification is included
#	only for future extensions. 
# stuart.h - As of 19 July 2018 only one attribute type is defined:
# 	14	Key Length (in bits)	TV
#
type IKEv2_DATA_ATTRIBUTE() = record {
	attribute_hdr: uint16;
	attribute_value: uint16;
} &let {
	# Split out A/F and type
	attribute_format: uint8 = attribute_hdr >> 15 & 1; 
	attribute_type: uint16 = attribute_hdr & 0x5fff;
} &byteorder=bigendian;

#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next Payload  |C|  RESERVED   |          Payload Length       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Diffie-Hellman Group Num   |             RESERVED          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# ~                       Key Exchange Data                       ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                     Key Exchange Payload Format
type IKEv2_KEY_EXCHANGE_PAYLOAD(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD) = record {
	DH_group_num: uint16;
	reserved: uint16;
	key_exchange_data: bytestring &length = payload.payload_hdr.payload_length - 8;
} &byteorder=bigendian;


#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next Payload  |C|  RESERVED   |         Payload Length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Cert Encoding |                                               |
# +-+-+-+-+-+-+-+-+                                               |
# ~                    Certification Authority                    ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                 Certificate Request Payload Format
type IKEv2_CERT_REQ_PAYLOAD(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD) = record {
	cert_encoding: uint8;
	cert_auth_data: uint8[payload.payload_hdr.payload_length - 5];
} &byteorder=bigendian;

#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next Payload  |C|  RESERVED   |         Payload Length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# ~                          Nonce Data                           ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                        Nonce Payload Format
type IKEv2_NONCE_PAYLOAD(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD) = record {
	nonce_data: bytestring &length=payload.payload_hdr.payload_length - 4;
} &byteorder=bigendian;

#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next Payload  |C|  RESERVED   |         Payload Length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Protocol ID  |    SPI Size   |       Notify Message Type     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# ~             Security Parameter Index (SPI)                    ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# ~                      Notification Data                        ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                      Notify Payload Format
type IKEv2_NOTIFY_PAYLOAD(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD) = record {
	protocol_id: uint8;
	spi_size: uint8;
	notify_message_type: uint16;
	spi: bytestring &length = spi_size;
	notification_data: bytestring &length = payload.payload_hdr.payload_length - 8 - spi_size;	
} &byteorder=bigendian;

#                      1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next Payload  |C|  RESERVED   |         Payload Length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# ~                        Vendor ID (VID)                        ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                      Vendor ID Payload Format
type IKEv2_VENDOR_ID_PAYLOAD(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD) = record {
	vendor_id: bytestring &length=payload.payload_hdr.payload_length - 4;
}

## End of type

refine connection IKEv2_Conn += {

	%member{
		int payload_;
	%}

	%init{
		payload_ = NO_NEXT_PAYLOAD;
	%}

	function get_next_payload()	:	int
		%{
			return payload_;
		%}

	function set_next_payload(payload:int)	:	bool
		%{
			payload_ = payload;
			return true;
		%}

};
