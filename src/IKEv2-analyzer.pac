%extern{
#include <cstdlib>
#include "DebugLogger.h"
%}

refine flow IKEv2_Flow += {

	function proc_IKEv2_message(pdu: IKEv2_PDU): 
	bool %{

		uint8 version = ${pdu.version};
		uint8 version_major = version >> 4;
		uint8 version_minor = version && 0x0F;

		DBG_LOG(DBG_PLUGINS, "IKEv2 MESSAGE - Version: %d", version_major);

		// We're only looking at IKEv2
		if (version_major != 2) {
			return false;
		}

		connection()->bro_analyzer()->ProtocolConfirmation();

		BifEvent::generate_ike_event(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			${pdu.is_orig},
			bytestring_to_val(${pdu.SAi}),
			bytestring_to_val(${pdu.SAr}),
			${pdu.next_payload},
			version_major,
			${pdu.exchange_type},
			${pdu.flags},
			${pdu.message_id},
			${pdu.length}
		);

		return true;
	
	%}

	function proc_IKEv2_sa_payload(payload: IKEv2_PAYLOAD, sa_payload: IKEv2_SA_PAYLOAD):
	bool %{
		
		DBG_LOG(DBG_PLUGINS, "IKE_SA_PAYLOAD");

		uint8 version = ${payload.pdu.version};
		uint8 version_major = version >> 4;
		uint8 version_minor = version && 0x0F;

		BifEvent::generate_ikev2_sa_init_event(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			${payload.pdu.is_orig},
			bytestring_to_val(${payload.pdu.SAi}),
			bytestring_to_val(${payload.pdu.SAr}),
			version_major
		);

		return true;

	%}

	function proc_IKEv2_proposal(pdu: IKEv2_PDU, proposal: IKEv2_PROPOSAL):
	bool %{

		DBG_LOG(DBG_PLUGINS, "IKE_SA_PROPOSAL");

		BifEvent::generate_ikev2_sa_init_proposal_event(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			${pdu.is_orig},
			bytestring_to_val(${pdu.SAi}),
			bytestring_to_val(${pdu.SAr}),
			${proposal.proposal_num},
			${proposal.num_transforms}
		);
		
		return true;

	%}

	function proc_IKEv2_data_attribute(data_attribute: IKEv2_DATA_ATTRIBUTE):
	bool %{

		DBG_LOG(DBG_PLUGINS, "IKE_SA_PROPOSAL_DATA_ATTRIBUTE");

		return true;

	%}

	function proc_IKEv2_transform(pdu: IKEv2_PDU, proposal: IKEv2_PROPOSAL, transform: IKEv2_TRANSFORM):
	bool %{

		DBG_LOG(DBG_PLUGINS, "IKA_SA_PROPOSAL_TRANSFORM");

		uint16 transform_value = 0;

		if (${transform}->has_data_attributes()) {
			transform_value = ${transform.data_attributes.attribute_value};
		}

		BifEvent::generate_ikev2_sa_init_transform_event(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			${pdu.is_orig},
			bytestring_to_val(${pdu.SAi}),
			bytestring_to_val(${pdu.SAr}),
			${proposal.proposal_num},
			${transform.transform_type},
			${transform.transform_id},
			transform_value
		);

		return true;

	%}

	function proc_ikev2_key_exchange_payload(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD, key_exchange: IKEv2_KEY_EXCHANGE_PAYLOAD):
	bool %{

		DBG_LOG(DBG_PLUGINS, "IKE_KEY_EXCHANGE");

		BifEvent::generate_ikev2_key_exchange_event(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			${pdu.is_orig},
			bytestring_to_val(${pdu.SAi}),
			bytestring_to_val(${pdu.SAr}),
			${key_exchange.DH_group_num},
			${key_exchange.reserved},
			${payload.payload_hdr.payload_length} - 8,
			bytestring_to_val(${key_exchange.key_exchange_data})
		);

		return true;

	%}

	function proc_IKEv2_data(pdu: IKEv2_PDU, IKEv2_data: IKEv2_DATA):
	bool %{

		return true;

	%}

	function proc_IKEv2_sa_init(pdu: IKEv2_PDU, sa_init: IKEv2_SA_INIT):
	bool %{

		DBG_LOG(DBG_PLUGINS, "IKE_SA_INIT");

		return true;

	%}

	function proc_IKEv2_payload(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD):
	bool %{

		DBG_LOG(DBG_PLUGINS, "IKE_PAYLOAD");

		return true;
	%}

	function proc_ikev2_nonce_payload(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD, nonce: IKEv2_NONCE_PAYLOAD):
	bool %{

		DBG_LOG(DBG_PLUGINS, "IKE_NONCE_PAYLOAD");

		BifEvent::generate_ikev2_nonce_payload_event (
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			${pdu.is_orig},
			bytestring_to_val(${pdu.SAi}),
			bytestring_to_val(${pdu.SAr}),
			${payload.payload_hdr.payload_length},
			bytestring_to_val(${nonce.nonce_data})
		);

		return true;

	%}

	function proc_ikev2_notify_payload(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD, notify_payload: IKEv2_NOTIFY_PAYLOAD):
	bool %{

		DBG_LOG(DBG_PLUGINS, "IKE_NOTIFY_PAYLOAD");

		BifEvent::generate_ikev2_notify_payload_event (
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			${pdu.is_orig},
			bytestring_to_val(${pdu.SAi}),
			bytestring_to_val(${pdu.SAr}),
			${notify_payload.protocol_id},
			${notify_payload.spi_size},
			${notify_payload.notify_message_type},
			bytestring_to_val(${notify_payload.spi}),
			bytestring_to_val(${notify_payload.notification_data})
		);
		
		return true;

	%}

	function proc_ikev2_vendor_id_payload(pdu: IKEv2_PDU, payload: IKEv2_PAYLOAD, vendor_id: IKEv2_VENDOR_ID_PAYLOAD):
	bool %{

		DBG_LOG(DBG_PLUGINS, "IKE_VENDOR_ID");

		BifEvent::generate_ikev2_vendor_id_event(
			connection()->bro_analyzer(),
			connection()->bro_analyzer()->Conn(),
			${pdu.is_orig},
			bytestring_to_val(${pdu.SAi}),
			bytestring_to_val(${pdu.SAr}),
			bytestring_to_val(${vendor_id.vendor_id})
		);

		return true;

	%}
};

# Top level IKEv2 packet
refine typeattr IKEv2_PDU += &let {
	proc: bool = $context.flow.proc_IKEv2_message(this);
};

# IKEv2 packet data
refine typeattr IKEv2_DATA += &let {
	proc: bool = $context.flow.proc_IKEv2_data(pdu, this);
}

# IKEv2 Payload
refine typeattr IKEv2_PAYLOAD += &let {
	proc: bool = $context.flow.proc_IKEv2_payload(pdu, this);
}

# Security Association Initiate Exchange (Exchange type 34)
refine typeattr IKEv2_SA_INIT += &let {
	proc: bool = $context.flow.proc_IKEv2_sa_init(pdu, this);
}

# Security Association Payload 
refine typeattr IKEv2_SA_PAYLOAD += &let {
	proc: bool = $context.flow.proc_IKEv2_sa_payload(payload, this);
};

# Proposal payload (2)
refine typeattr IKEv2_PROPOSAL += &let {
	proc: bool = $context.flow.proc_IKEv2_proposal(pdu, this);
};

# Transform payload (3)
refine typeattr IKEv2_TRANSFORM += &let {
	proc: bool = $context.flow.proc_IKEv2_transform(pdu, proposal, this);
};

# Transform data attributes
refine typeattr IKEv2_DATA_ATTRIBUTE += &let {
	proc: bool = $context.flow.proc_IKEv2_data_attribute(this);
};

# Key exchange payload (34)
refine typeattr IKEv2_KEY_EXCHANGE_PAYLOAD += &let {
	proc: bool = $context.flow.proc_ikev2_key_exchange_payload(pdu, payload, this);
}

# Nonce payload (40)
refine typeattr IKEv2_NONCE_PAYLOAD += &let {
	proc: bool = $context.flow.proc_ikev2_nonce_payload(pdu, payload, this);
}

# Notify payload (41)
refine typeattr IKEv2_NOTIFY_PAYLOAD += &let {
	proc: bool = $context.flow.proc_ikev2_notify_payload(pdu, payload, this);
}

# Vendor ID payload (43)
refine typeattr IKEv2_VENDOR_ID_PAYLOAD += &let {
	proc: bool = $context.flow.proc_ikev2_vendor_id_payload(pdu, payload, this);
}