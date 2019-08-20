signature dpd_ikev2 {
	
	ip-proto == udp

	# A signature to identify IKEv2 traffic
	#
	# 17th byte is next payload in the IKE header.
	# - We expect to see something in the range 33 (0x21) to 54 (0x36) 
	# 
	# 18th byte is version number in the IKE header
	# - This should be 0x20 as we're only looking at IKEv2
	# 
	# 19th byte is exchange type in the IKE header. 
	# - We expect to see something in the range 34 (0x22) to 41 (0x29)
	#
	# 29th byte is next payload field in the first generic payload header after the IKE header
	# - We expect to see something in the range 34 (0x22) to 41 (0x29)	
	payload /^.{16}[\x21-\x36]\x20[\x22-\x29].{9}[\x22-\x29]/

	enable "ikev2"

}
