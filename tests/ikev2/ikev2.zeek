# @TEST-EXEC: zeek -C -r $TRACES/ikev2.pcap %INPUT
# @TEST-EXEC: btest-diff ikev2.log
# @TEST-EXEC: btest-diff conn.log
