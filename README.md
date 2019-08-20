
Zeek Plugin IKEv2
=================

A IKEv2 protocol analyzer for Zeek.

This protocol analyzer focuses on the IKE_SA_INIT exchange which is unencrypted and used to establish a secure tunnel.

Useful information such as SPIs, cipher proposals, and vendor IDs are contained in these packets.

# Installation and Usage

zeek-plugin-ikev2 is distributed as a Zeek package and is compatible with the zkg command line tool.

# main.zeek

The main.zeek script generates an ikev2.log log file containing the IKE_SA_INIT response from the VPN gateway with details of the selected cryptographic proposal selected to establish the connection.

|Field                     |Description                                                  |
|--------------------------|-------------------------------------------------------------|
|ts                        |Timestamp                                                    |
|uid                       |Connection ID                                                |
|id.orig_h                 |Originating host                                             |
|id.orig_p                 |Originating port                                             |
|id.resp_h                 |Responding host                                              |
|id.resp_p                 |Responding post                                              |
|is_orig                   |Packet from originator                                       |
|sa_i                      |Initiators SPI                                               |
|sa_r                      |Responders SPI                                               | 
|version                   |IKE version                                                  |
|exchange_type             |IKE exchange type                                            |
|selected_proposal_number  |Selected proposal number                                     |
|selected_transforms       |List of transforms selected                                  |
|selected_ke_dh_group_num  |Key exchange Diffie-Helleman group number                    |
|cipher_hash               |MD5 hash of selected_transforms and selected_ke_dh_group_num |
|notify_message_type_names |List of notify message types                                 |
|vendor_payloads           |List of vendor payloads                                      |

# Acknowledgements

* Thanks to Adam R @ukncsc for peer review

# Maintenance

This plugin is a side product and so maintenance will be on a best efforts basis.

# Copyright

Crown Copyright 2020.

# License

Like Zeek, this plugin comes with a BSD license, allowing for free use with virtually no
restrictions. You can find it [here](https://github.com/ukncsc/zeek-plugin-ikev2/blob/master/COPYING).