# Implements base functionality for IKEv2 analysis.
# Generates the ikev2.log file.

@load base/frameworks/notice/weird
@load ./consts

module IKEv2;

export {
	redef enum Log::ID += { IKEv2_LOG };

	type IKEv2::Info: record {
		# Timestamp for when the event happened.
		ts:     time    &log;
		# Unique ID for the connection.
		uid:    string  &log;
		# The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;
		# Is orig
		is_orig:	bool &log &optional;
		# The initiators SA SPI
		sa_i:	string	&log &optional;
		# The responders SA SPI
		sa_r:	string	&log &optional;
		# Protocol version
		version: int	&log &optional;
		# Exchange type
		exchange_type: int 	&log &optional;
		# Selected proposal number
		selected_proposal_number: string &log &optional;
		# Selected transforms
		selected_transforms: vector of string &log &optional;
		# Selected key exchange DH group number
		selected_ke_dh_group_num: int	&log &optional;
		# Cipher hash
		cipher_hash: string &log &optional;
		# Notify payloads types		
		notify_message_type_names:	vector of string &log &optional;
		# Vendor payloads
		vendor_payloads:	vector of string &log &optional &optional;
		# The analyzer ID used for the analyzer instance attached
		# to each connection.  It is not used for logging since it's a
		# meaningless arbitrary number.
		analyzer_id:      count            &optional;
	};

	# Event that can be handled to access the IKEv2 record as it is sent on
	# to the logging framework.
	global log_ikev2: event(rec: IKEv2::Info);
}

const ike_ports = { 500/udp, 4500/udp };

redef likely_server_ports += { ike_ports };

redef record connection += {
	ikev2: Info &optional;
};

event zeek_init() &priority=5
{	
	Log::create_stream(IKEv2::IKEv2_LOG, [$columns=Info, $ev=log_ikev2, $path="ikev2"]);
}

function set_session(c: connection)
	{
	if ( ! c?$ikev2 )
		c$ikev2 = [$ts=network_time(), $uid=c$uid, $id=c$id];
	}

event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count) &priority=5
	{
	if ( atype == Analyzer::ANALYZER_IKEV2 )
		{
		set_session(c);
		c$ikev2$analyzer_id = aid;
		}
	}

event ike_event(
	c: connection,
	is_orig: bool,
	sa_i: string,
    sa_r: string,
    first_payload: int,
    version: int,
    exchange_type: int,
	flags: int,
    message_id: int,
    length: int
)
	{

		# We're only looking at responses from the VPN gateway
		if ( is_orig )
			return;

		# We're only interested in IKE_SA_INITs
		if (exchange_type != 34) {
			return;
		}

		set_session(c);
		
		c$ikev2$is_orig = is_orig;
		c$ikev2$sa_i = bytestring_to_hexstr(sa_i);
		c$ikev2$sa_r = bytestring_to_hexstr(sa_r);
		c$ikev2$version = version;

		if (c$ikev2?$selected_transforms && c$ikev2?$selected_ke_dh_group_num) {
			local cipher_string = string_cat(cat(c$ikev2$selected_transforms,c$ikev2$selected_ke_dh_group_num));
			c$ikev2$cipher_hash = md5_hash(cipher_string);
		}

		Log::write(IKEv2::IKEv2_LOG, c$ikev2);

		delete c$ikev2;
	}

event ikev2_sa_init_event(
 	c: connection,
	is_orig: bool,
 	sa_i: string,
 	sa_r: string,
 	version: int
)
 	{
		set_session(c);

		# If this event is raised the exchange type must be 34
		c$ikev2$exchange_type = 34;
 	}

event ikev2_sa_init_proposal_event(
	c: connection,
	is_orig: bool,
	sa_i: string,
	sa_r: string,
	proposal_num: int,
	num_transforms: int
)
	{
		set_session(c);

		if ( is_orig )
			return;

		c$ikev2$selected_proposal_number = fmt("%d", proposal_num);

		return;
	}

event ikev2_sa_init_transform_event(
 	c: connection,
	is_orig: bool,
 	sa_i: string,
 	sa_r: string,
 	proposal_num: count,
 	transform_type: count,
 	transform_id: count,
 	transform_value: int
 )
 	{
 		set_session(c);

		if ( is_orig )
			return;

		if ( ! c$ikev2?$selected_transforms )
			c$ikev2$selected_transforms = vector();

		local transform_id_string: string;
		
 		if (transform_type == 1) { # Encryption Algorithm (ENCR)
			transform_id_string = encryption_transform_ids[transform_id];
 		} else if (transform_type == 2) { #Pseudorandom Function (PRF)
 			transform_id_string = prf_transform_ids[transform_id];
 		} else if (transform_type == 3) { #Integrity Algorithm (INTEG)
 			transform_id_string = integrity_transform_ids[transform_id];
 		} else if (transform_type == 4) { #Diffie-Hellman Group (D-H)
 			transform_id_string = dhgroup_transform_ids[transform_id];
 		} else if (transform_type == 5) { #Extended Sequence Numbers (ESN)
 			transform_id_string = esn_transform_ids[transform_id];
 		} else {
 			# Weird - should never happen
			Reporter::conn_weird("ikev2_unknown_transform_type", c, "");
 			transform_id_string = fmt("UNKNOWN:%d", transform_type);
 		}

		c$ikev2$selected_transforms += fmt("%s:%s", transform_types_short[transform_type], transform_id_string);
 	
		return;
 	}

event ikev2_key_exchange_event(
 	c: connection,
	is_orig: bool,
 	sa_i: string,
 	sa_r: string,
 	dh_group_num: int,
 	reserved: int,
 	key_exchange_size: int,
 	key_exchange_data: string
 )
 	{

		set_session(c);

 		c$ikev2$selected_ke_dh_group_num = dh_group_num;

		# Reserved should always be 0
		if ( reserved != 0 )
			Reporter::conn_weird("ikev2_key_exchange_reserver_non_zero", c, "");

 	}

event ikev2_notify_payload_event (
	c: connection,
	is_orig: bool,
	sa_i: string,
	sa_r: string,
	protocol_id: int,
	spi_size: int,
	notify_message_type: count,
	spi: string,
	notification_data: string
)
	{

		if ( is_orig )
			return;

		if ( ! c$ikev2?$notify_message_type_names)
			c$ikev2$notify_message_type_names = vector();

		c$ikev2$notify_message_type_names += notify_message_types[notify_message_type];
			
		set_session(c);

	}

event ikev2_vendor_id_event (
	c: connection,
	is_orig: bool,
	sa_i: string,
	sa_r: string,
	vendor_id: string
)
	{

		set_session(c);

		if ( ! c$ikev2?$vendor_payloads )
				c$ikev2$vendor_payloads = vector();

		local vendor_id_friendly_name: string;
		vendor_id_friendly_name = fmt("UNKNOWN:%s", bytestring_to_hexstr(vendor_id));

 		# Attempt to get friendly name for Vendor ID
 		for (i in vendor_ids)
 		{
 			if(vendor_ids[i] in bytestring_to_hexstr(vendor_id))
 			{
 				vendor_id_friendly_name = i;
 				break;
 			}
 		}

		c$ikev2$vendor_payloads += vendor_id_friendly_name;

 	}