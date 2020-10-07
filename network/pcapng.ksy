meta:
  id: pcapng
  file-extension:
    - pcapng
  license: CC0-1.0
  ks-version: 0.8
  endian: le
  imports:
    - /network/ethernet_frame
    - /network/packet_ppi
doc: |
  PCAPNG (PCAP Next Generation) is the next generation file format
  for saving network traffic grabbed by network sniffers. It is
  typically produced by tools like [tcpdump](https://www.tcpdump.org/)
  or [Wireshark](https://www.wireshark.org/).
doc-ref: https://github.com/pcapng/pcapng
seq:
  - id: sections
    type: section
    repeat: eos
types:
  section:
    seq:
      - id: type
        -orig-id: Block Type
        contents: [ 0x0A, 0x0D, 0x0D, 0x0A ]
      - id: raw_block_len
        -orig-id: Block Total Length
        type: u1
        repeat: expr
        repeat-expr: 4
      - id: byte_order
        -orig-id: Byte-Order Magic
        type: u1
        repeat: expr
        repeat-expr: 4
      - id: section_header
        type: section_header_block_part2
      - id: blocks
        type: block
        repeat: until
        repeat-until: _io.eof or _io.pos + _.block_len > section_header.section_len
    instances:
      is_big_endian:
        value: 'byte_order.first==0x1A ? true : false'
      block_len:
        # calculated according to byte_order
        value: 'is_big_endian ? raw_block_len[0]*0x1000000 + raw_block_len[1]*0x10000 + raw_block_len[2]*0x100 + raw_block_len[3] : raw_block_len[3]*0x1000000 + raw_block_len[2]*0x10000 + raw_block_len[1]*0x100 + raw_block_len[0]'
  padding4: # padding to 4 bytes
    params:
      - id: len_value
        type: u2
    seq:
      - id: padding
        size: size
        if: size > 0
    instances:
      size:
        value: (len_value + 3) / 4 * 4 - len_value
  options:
    params:
      - id: block_type
        type: u4
        enum: blocktype
    seq:
      - id: options
        type:
          switch-on: block_type
          cases:
            'blocktype::section_header.to_i': option_shb
            'blocktype::interface_description.to_i': option_idb
            'blocktype::enhanced_packet.to_i': option_epb
            'blocktype::interface_statistics.to_i': option_isb
            'blocktype::name_resolution.to_i': option_nrb
            _ : option_common
        repeat: eos
  option_common:
    seq:
      - id: type
        -orig-id: Option Code
        type: u2
        enum: optcode_common
      - id: len_value
        -orig-id: Option Length
        type: u2
      - id: value
        -orig-id: Option Value
        size: len_value
      - id: padding
        type: padding4(len_value)
  option_shb:
    seq:
      - id: type
        -orig-id: Option Code
        type: u2
        enum: optcode_shb
      - id: len_value
        -orig-id: Option Length
        type: u2
      - id: value
        -orig-id: Option Value
        size: len_value
      - id: padding
        type: padding4(len_value)
  option_idb:
    seq:
      - id: type
        -orig-id: Option Code
        type: u2
        enum: optcode_idb
      - id: len_value
        -orig-id: Option Length
        type: u2
      - id: value
        -orig-id: Option Value
        size: len_value
      - id: padding
        type: padding4(len_value)
  option_epb:
    seq:
      - id: type
        -orig-id: Option Code
        type: u2
        enum: optcode_epb
      - id: len_value
        -orig-id: Option Length
        type: u2
      - id: value
        -orig-id: Option Value
        size: len_value
      - id: padding
        type: padding4(len_value)
  option_isb:
    seq:
      - id: type
        -orig-id: Option Code
        type: u2
        enum: optcode_isb
      - id: len_value
        -orig-id: Option Length
        type: u2
      - id: value
        -orig-id: Option Value
        size: len_value
      - id: padding
        type: padding4(len_value)
  option_nrb:
    seq:
      - id: type
        -orig-id: Option Code
        type: u2
        enum: optcode_nrb
      - id: len_value
        -orig-id: Option Length
        type: u2
      - id: value
        -orig-id: Option Value
        size: len_value
      - id: padding
        type: padding4(len_value)
  block:
    meta:
      endian:
        switch-on: _parent.is_big_endian
        cases:
          'true': be
          'false': le
    seq:
      - id: type
        -orig-id: Block Type
        type: u4
        enum: blocktype
      - id: block_len
        -orig-id: Block Total Length
        type: u4
      - id: body
        size: block_len - common_len
        type:
          switch-on: type
          cases:
            'blocktype::interface_description': interface_desc_blk
            'blocktype::enhanced_packet': enhanced_pkt_blk
            'blocktype::simple_packet': simple_pkt_blk
            'blocktype::interface_statistics': interface_statistics_blk
            'blocktype::name_resolution': name_resolution_blk
            'blocktype::systemd_journal_export': systemd_journal_export_blk
            'blocktype::decryption_secrets': decryption_secrets_blk
            'blocktype::custom_1': custom_blk
            'blocktype::custom_2': custom_blk
      - id: block_len2
        -orig-id: Block Total Length
        type: u4
    instances:
      common_len:
        # block type + 2 * total len = 12
        value: 12
  section_header_block_part2:
    meta:
      endian:
        switch-on: _parent.is_big_endian
        cases:
          'true': be
          'false': le
    seq:
      - id: version_major
        -orig-id: Major Version
        type: u2
      - id: version_minor
        -orig-id: Minor Version
        type: u2
      - id: section_len # excluding SHB itself
        -orig-id: Section Length
        type: u8
      - id: options
        -orig-id: Options
        type: options(blocktype::section_header.to_i)
        size: _parent.block_len - 12 - 16
        if: _parent.block_len - 12 - 16 > 0
      - id: block_len2
        type: u4
  interface_desc_blk:
    seq:
      - id: network
        -orig-id: LinkType
        type: u2
        enum: linktype
      - id: reserved
        -orig-id: Reserved
        type: u2
      - id: snap_len
        -orig-id: SnapLen
        type: u4
      - id: options
        -orig-id: Options
        type: options(_parent.type.to_i)
        size: _parent.block_len - _parent.common_len - 8
        if: _parent.block_len - _parent.common_len - 8 > 0
  enhanced_pkt_blk:
    seq:
      - id: interface_id
        -orig_id: Interface ID
        type: u4
      - id: timestamp_high
        -orig_id: Timestamp (High)
        type: u4
      - id: timestamp_low
        -orig_id: Timestamp (Low)
        type: u4
      - id: captured_len
        -orig_id: Captured Packet Length
        type: u4
      - id: original_len
        -orig_id: Original Packet Length
        type: u4
      - id: packet
        -orig_id: Packet Data
        size: captured_len
        type:
          switch-on: idb.network
          cases:
            'linktype::ppi': packet_ppi
            'linktype::ethernet': ethernet_frame
      - id: padding
        type: padding4(captured_len)
      - id: options
        -orig-id: Options
        type: options(_parent.type.to_i)
        size: len_options
        if: len_options > 0
    instances:
      len_options:
        value: _parent.block_len - _parent.common_len - 20 - captured_len - padding.size
      idb:
        value: _parent._parent.blocks[interface_id].body.as<interface_desc_blk>
  simple_pkt_blk:
    seq:
      - id: len_packet
        -orig_id: Original Packet Length
        type: u4
      - id: packet
        -orig_id: Packet Data
        size: len_packet
        type:
          switch-on: idb.network
          cases:
            'linktype::ppi': packet_ppi
            'linktype::ethernet': ethernet_frame
    instances:
      idb:
        value: _parent._parent.blocks[0].body.as<interface_desc_blk>
  name_resolution_blk:
    seq:
      - id: records
        type: name_resolution_record
        repeat: until
        repeat-until: _.type == nrrtype::end
      - id: options
        -orig-id: Options
        type: options(_parent.type.to_i)
        size-eos: true
  name_resolution_record:
    seq:
      - id: type
        -orig-id: Record Type
        type: u2
        enum: nrrtype
      - id: len_value
        -orig-id: Record Value Length
        type: u2
      - id: value
        -orig-id: Record Value
        size: len_value
        type:
          switch-on: type
          cases:
            'nrrtype::ipv4': name_resolution_ipv4
            'nrrtype::ipv6': name_resolution_ipv6
  name_resolution_ipv4:
    seq:
      - id: ip_addr
        size: 4
      - id: dns_entries
        type: strz
        encoding: UTF-8
        repeat: eos
  name_resolution_ipv6:
    seq:
      - id: ip_addr
        size: 16
      - id: dns_entries
        type: strz
        encoding: UTF-8
        repeat: eos
  interface_statistics_blk:
    seq:
      - id: interface_id
        -orig_id: Interface ID
        type: u4
      - id: timestamp_high
        -orig_id: Timestamp (High)
        type: u4
      - id: timestamp_low
        -orig_id: Timestamp (Low)
        type: u4
      - id: options
        -orig-id: Options
        type: options(_parent.type.to_i)
        size: len_options
        if: len_options > 0
    instances:
      len_options:
        value: _parent.block_len - _parent.common_len - 12
  systemd_journal_export_blk:
    seq:
      - id: entries
        -orig_id: Journal Entry
        size: _parent.block_len - _parent.common_len
  decryption_secrets_blk:
    seq:
      - id: secrets_type
        -orig-id: Secrets Type
        type: u4
        enum: sectypes
      - id: len_data
        -orig-id: Secrets Length
        type: u4
      - id: data
        -orig-id: Secrets Data
        type: u4
      - id: padding
        type: padding4(len_data)
      - id: options
        -orig-id: Options
        type: options(_parent.type.to_i)
        size: len_options
        if: len_options > 0
    instances:
      len_options:
        value: _parent.block_len - _parent.common_len - 12
  custom_blk:
    seq:
      - id: pen
        -orig-id: Private Enterprise Number (PEN)
        type: u4
      - id: data_and_options
        # Don't know how to seperate custom data from options
        size: _parent.block_len - _parent.common_len - 4
enums:
  blocktype:
    0x00000001: interface_description
    0x00000002: packet
    0x00000003: simple_packet
    0x00000004: name_resolution
    0x00000005: interface_statistics
    0x00000006: enhanced_packet
    0x00000007: irig_timestamp
    0x00000008: arinc_429
    0x00000009: systemd_journal_export
    0x0000000A: decryption_secrets
    0x00000101: hone_project_machine_info
    0x00000102: hone_project_connection_event
    0x00000201: sysdig_machine_info
    0x00000202: sysdig_process_info_v1
    0x00000203: sysdig_fd_list
    0x00000204: sysdig_event
    0x00000205: sysdig_interface_list
    0x00000206: sysdig_user_list
    0x00000207: sysdig_process_info_v2
    0x00000208: sysdig_event
    0x00000209: sysdig_process_info_v3
    0x00000210: sysdig_process_info_v4
    0x00000211: sysdig_process_info_v5
    0x00000212: sysdig_process_info_v6
    0x00000213: sysdig_process_info_v7
    0x00000BAD: custom_1
    0x40000BAD: custom_2
    0x0A0D0D0A: section_header
  linktype:
    # http://www.tcpdump.org/linktypes.html
    0: null_linktype
    1: ethernet
    3: ax25
    6: ieee802_5
    7: arcnet_bsd
    8: slip
    9: ppp
    10: fddi
    50: ppp_hdlc
    51: ppp_ether
    100: atm_rfc1483
    101: raw
    104: c_hdlc
    105: ieee802_11
    107: frelay
    108: loop
    113: linux_sll
    114: ltalk
    117: pflog
    119: ieee802_11_prism
    122: ip_over_fc
    123: sunatm
    127: ieee802_11_radiotap
    129: arcnet_linux
    138: apple_ip_over_ieee1394
    139: mtp2_with_phdr
    140: mtp2
    141: mtp3
    142: sccp
    143: docsis
    144: linux_irda
    147: user0
    148: user1
    149: user2
    150: user3
    151: user4
    152: user5
    153: user6
    154: user7
    155: user8
    156: user9
    157: user10
    158: user11
    159: user12
    160: user13
    161: user14
    162: user15
    163: ieee802_11_avs
    165: bacnet_ms_tp
    166: ppp_pppd
    169: gprs_llc
    170: gpf_t
    171: gpf_f
    177: linux_lapd
    187: bluetooth_hci_h4
    189: usb_linux
    192: ppi
    195: ieee802_15_4
    196: sita
    197: erf
    201: bluetooth_hci_h4_with_phdr
    202: ax25_kiss
    203: lapd
    204: ppp_with_dir
    205: c_hdlc_with_dir
    206: frelay_with_dir
    209: ipmb_linux
    215: ieee802_15_4_nonask_phy
    220: usb_linux_mmapped
    224: fc_2
    225: fc_2_with_frame_delims
    226: ipnet
    227: can_socketcan
    228: ipv4
    229: ipv6
    230: ieee802_15_4_nofcs
    231: dbus
    235: dvb_ci
    236: mux27010
    237: stanag_5066_d_pdu
    239: nflog
    240: netanalyzer
    241: netanalyzer_transparent
    242: ipoib
    243: mpeg_2_ts
    244: ng40
    245: nfc_llcp
    247: infiniband
    248: sctp
    249: usbpcap
    250: rtac_serial
    251: bluetooth_le_ll
    253: netlink
    254: bluetooth_linux_monitor
    255: bluetooth_bredr_bb
    256: bluetooth_le_ll_with_phdr
    257: profibus_dl
    258: pktap
    259: epon
    260: ipmi_hpm_2
    261: zwave_r1_r2
    262: zwave_r3
    263: wattstopper_dlm
    264: iso_14443
  optcode_common:
    0: end_of_opt
    1: comment
    2988: custom_utf8_1
    2989: custom_bin_1
    19372: custom_utf8_2
    19373: custom_bin_2
  optcode_shb:
    0: end_of_opt
    1: comment
    2988: custom_utf8_1
    2989: custom_bin_1
    19372: custom_utf8_2
    19373: custom_bin_2
    # for SHB
    2: shb_hardware
    3: shb_os
    4: shb_userappl
  optcode_idb:
    0: end_of_opt
    1: comment
    2988: custom_utf8_1
    2989: custom_bin_1
    19372: custom_utf8_2
    19373: custom_bin_2
    # for IPB
    2: if_name
    3: if_description
    4: if_ipv4_addr
    5: if_ipv6_addr
    6: if_mac_addr
    7: if_eui_addr
    8: if_speed
    9: if_tsresol
    10: if_tzone
    11: if_filter
    12: if_os
    13: if_fcslen
    14: if_tsoffset
    15: if_hardware
  optcode_epb:
    0: end_of_opt
    1: comment
    2988: custom_utf8_1
    2989: custom_bin_1
    19372: custom_utf8_2
    19373: custom_bin_2
    # for EPB
    2: epb_flags
    3: epb_hash
    4: epb_dropcount
  optcode_isb:
    0: end_of_opt
    1: comment
    2988: custom_utf8_1
    2989: custom_bin_1
    19372: custom_utf8_2
    19373: custom_bin_2
    # for ISB
    2: isb_starttime
    3: isb_endtime
    4: isb_ifrecv
    5: isb_ifdrop
    6: isb_filteraccept
    7: isb_osdrop
    8: isb_usrdeliv
  optcode_nrb:
    0: end_of_opt
    1: comment
    2988: custom_utf8_1
    2989: custom_bin_1
    19372: custom_utf8_2
    19373: custom_bin_2
    # for NRB
    2: ns_dnsname
    3: ns_dnsip4addr
    4: ns_dnsip6addr
  nrrtype: # Name Resolution Record Type
    0x0000: end
    0x0001: ipv4
    0x0002: ipv6
  sectypes: # Secrets Types
    0x544c534b: tls_key_log       # TLS Key Log
    0x57474b4c: wireguard_key_log # WireGuard Key Log.

