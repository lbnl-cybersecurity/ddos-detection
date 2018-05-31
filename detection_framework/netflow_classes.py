

# This module contains classes for handling Netflow v9 data.

#!/usr/bin/env python3

"""
Classes were created originally for Dominik Pataky's collector.

Netflow V9 collector and parser implementation in Python 3.
Created for learning purposes and unsatisfying alternatives.
This script is specifically implemented in combination with softflowd.
See https://github.com/djmdjm/softflowd
(C) 2016 Dominik Pataky <dom@netdecorator.org>
Licensed under MIT License. See LICENSE.
"""

import socket
import struct
import sys

HOST = '0.0.0.0'  #sys.argv[1]
PORT = 2347  #int(sys.argv[2])
#sock.bind(('0.0.0.0', 2346))

field_types = {
    1: 'IN_BYTES',
    2: 'IN_PKTS',
    3: 'FLOWS',
    4: 'PROTOCOL',
    5: 'SRC_TOS',
    6: 'TCP_FLAGS',
    7: 'L4_SRC_PORT',
    8: 'IPV4_SRC_ADDR',
    9: 'SRC_MASK',
    10: 'INPUT_SNMP',
    11: 'L4_DST_PORT',
    12: 'IPV4_DST_ADDR',
    13: 'DST_MASK',
    14: 'OUTPUT_SNMP',
    15: 'IPV4_NEXT_HOP',
    16: 'SRC_AS',
    17: 'DST_AS',
    18: 'BGP_IPV4_NEXT_HOP',
    19: 'MUL_DST_PKTS',
    20: 'MUL_DST_BYTES',
    21: 'LAST_SWITCHED',
    22: 'FIRST_SWITCHED',
    23: 'OUT_BYTES',
    24: 'OUT_PKTS',
    25: 'MIN_PKT_LNGTH',
    26: 'MAX_PKT_LNGTH',
    27: 'IPV6_SRC_ADDR',
    28: 'IPV6_DST_ADDR',
    29: 'IPV6_SRC_MASK',
    30: 'IPV6_DST_MASK',
    31: 'IPV6_FLOW_LABEL',
    32: 'ICMP_TYPE',
    33: 'MUL_IGMP_TYPE',
    34: 'SAMPLING_INTERVAL',
    35: 'SAMPLING_ALGORITHM',
    36: 'FLOW_ACTIVE_TIMEOUT',
    37: 'FLOW_INACTIVE_TIMEOUT',
    38: 'ENGINE_TYPE',
    39: 'ENGINE_ID',
    40: 'TOTAL_BYTES_EXP',
    41: 'TOTAL_PKTS_EXP',
    42: 'TOTAL_FLOWS_EXP',
    # 43 vendor proprietary
    44: 'IPV4_SRC_PREFIX',
    45: 'IPV4_DST_PREFIX',
    46: 'MPLS_TOP_LABEL_TYPE',
    47: 'MPLS_TOP_LABEL_IP_ADDR',
    48: 'FLOW_SAMPLER_ID',
    49: 'FLOW_SAMPLER_MODE',
    50: 'NTERVAL',
    # 51 vendor proprietary
    52: 'MIN_TTL',
    53: 'MAX_TTL',
    54: 'IPV4_IDENT',
    55: 'DST_TOS',
    56: 'IN_SRC_MAC',
    57: 'OUT_DST_MAC',
    58: 'SRC_VLAN',
    59: 'DST_VLAN',
    60: 'IP_PROTOCOL_VERSION',
    61: 'DIRECTION',
    62: 'IPV6_NEXT_HOP',
    63: 'BPG_IPV6_NEXT_HOP',
    64: 'IPV6_OPTION_HEADERS',
    # 65-69 vendor proprietary
    70: 'MPLS_LABEL_1',
    71: 'MPLS_LABEL_2',
    72: 'MPLS_LABEL_3',
    73: 'MPLS_LABEL_4',
    74: 'MPLS_LABEL_5',
    75: 'MPLS_LABEL_6',
    76: 'MPLS_LABEL_7',
    77: 'MPLS_LABEL_8',
    78: 'MPLS_LABEL_9',
    79: 'MPLS_LABEL_10',
    80: 'IN_DST_MAC',
    81: 'OUT_SRC_MAC',
    82: 'IF_NAME',
    83: 'IF_DESC',
    84: 'SAMPLER_NAME',
    85: 'IN_PERMANENT_BYTES',
    86: 'IN_PERMANENT_PKTS',
    # 87 vendor property
    88: 'FRAGMENT_OFFSET',
    89: 'FORWARDING STATUS',
}


class DataRecord:
    """This is a 'flow' as we want it from our source. What it contains is
    variable in NetFlow V9, so to work with the data you have to analyze the
    data dict keys (which are integers and can be mapped with the field_types
    dict).
    Should hold a 'data' dict with keys=field_type (integer) and value (in bytes).
    """
    def __init__(self):
        self.data = {}

    def __repr__(self):
        return "<DataRecord with data: {}>".format(self.data)


class DataFlowSet:
    """Holds one or multiple DataRecord which are all defined after the same
    template. This template is referenced in the field 'flowset_id' of this
    DataFlowSet and must not be zero.
    """
    def __init__(self, data, templates):
        pack = struct.unpack('!HH', data[:4])

        self.template_id = pack[0]  # flowset_id is reference to a template_id
        self.length = pack[1]
        self.flows = []

        offset = 4
        template = templates[self.template_id]

        # As the field lengths are variable V9 has padding to next 32 Bit
        padding_size = 4 - (self.length % 4)  # 4 Byte

        while offset <= (self.length - padding_size):
            new_record = DataRecord()

            for field in template.fields:
                flen = field.field_length
                fkey = field_types[field.field_type]
                fdata = None

                # The length of the value byte slice is defined in the template
                dataslice = data[offset:offset+flen]

                # Better solution than struct.unpack with variable field length
                fdata = 0
                for idx, byte in enumerate(reversed(bytearray(dataslice))):
                    fdata += byte << (idx * 8)

                new_record.data[fkey] = fdata

                offset += flen

            self.flows.append(new_record)

    def __repr__(self):
        return "<DataFlowSet with template {} of length {} holding {} flows>"\
            .format(self.template_id, self.length, len(self.flows))


class TemplateField:
    """A field with type identifier and length.
    """
    def __init__(self, field_type, field_length):
        self.field_type = field_type  # integer
        self.field_length = field_length  # bytes

    def __repr__(self):
        return "<TemplateField type {}:{}, length {}>".format(
            self.field_type, field_types[self.field_type], self.field_length)


class TemplateRecord:
    """A template record contained in a TemplateFlowSet.
    """
    def __init__(self, template_id, field_count, fields):
        self.template_id = template_id
        self.field_count = field_count
        self.fields = fields

    def __repr__(self):
        return "<TemplateRecord {} with {} fields: {}>".format(
            self.template_id, self.field_count,
            ' '.join([field_types[field.field_type] for field in self.fields]))


class TemplateFlowSet:
    """A template flowset, which holds an id that is used by data flowsets to
    reference back to the template. The template then has fields which hold
    identifiers of data types (eg "IP_SRC_ADDR", "PKTS"..). This way the flow
    sender can dynamically put together data flowsets.
    """
    def __init__(self, data):
        pack = struct.unpack('!HH', data[:4])
        self.flowset_id = pack[0]
        self.length = pack[1]  # total length including this header in bytes
        self.templates = {}

        offset = 4  # Skip header

        # Iterate through all template records in this template flowset
        while offset != self.length:
            pack = struct.unpack('!HH', data[offset:offset+4])
            template_id = pack[0]
            field_count = pack[1]

            fields = []
            for field in range(field_count):
                # Get all fields of this template
                offset += 4
                field_type, field_length = struct.unpack('!HH', data[offset:offset+4])
                field = TemplateField(field_type, field_length)
                fields.append(field)

            # Create a tempalte object with all collected data
            template = TemplateRecord(template_id, field_count, fields)

            # Append the new template to the global templates list
            self.templates[template.template_id] = template

            # Set offset to next template_id field
            offset += 4

    def __repr__(self):
        return "<TemplateFlowSet with id {} of length {} containing templates: {}>"\
            .format(self.flowset_id, self.length, self.templates.keys())


class Header:
    """The header of the ExportPacket.
    """
    def __init__(self, data):
        pack = struct.unpack('!HHIIII', data[:20])

        self.version = pack[0]
        self.count = pack[1]  # not sure if correct. softflowd: no of flows
        self.uptime = pack[2]
        self.timestamp = pack[3]
        self.sequence = pack[4]
        self.source_id = pack[5]


class ExportPacket:
    """The flow record holds the header and all template and data flowsets.
    """
    def __init__(self, data, templates):
        self.header = Header(data)
        self.templates = templates
        self.flows = []

        offset = 20
        while offset != len(data):
            flowset_id = struct.unpack('!H', data[offset:offset+2])[0]
            if flowset_id == 0:  # TemplateFlowSet always have id 0
                tfs = TemplateFlowSet(data[offset:])
                self.templates.update(tfs.templates)
                offset += tfs.length
            else:
                dfs = DataFlowSet(data[offset:], self.templates)
                self.flows += dfs.flows
                offset += dfs.length

    def __repr__(self):
        return "<ExportPacket version {} counting {} records>".format(
            self.header.version, self.header.count)

class Flow:
        """ Individual flow object, used for detection tests
        Not all fields may be present in NetFlow v9 data.
        Update a Flow object for every flow read in a stream or from an nfdump file. 
        """
        name = ''
        average = 0.0
        values = None # list cannot be initialized here!
        bytes_rcvd = 0
        pkts_rcvd = 0
        flows = 0
        protocol = ''
        src_tos = 0
        tcp_flags = ''
        src_port = 0
        src_mask = 0
        input_snmp = 0
        dst_port = 0
        dst_addr = 0
        dst_mask = 0
        output_snmp = 0
        ipv4_next_hop = 0
        src_as = 0
        dst_as = 0
        bgp_ipv4_next_hop = 0
        mul_dst_pkts =  0
        mul_dst_bytes = 0
        last_switched = 0
        first_switched = 0
        out_bytes = 0
        out_pkts = 0
        min_pkt_lngth = 0
        max_pkt_lngth = 0
        ipv6_src_ip = 0
        ipv6_dst_ip = 0
        ipv6_dst_mask = 0
        ipv6_flow_label = 0
        icmp_type = 0
        mul_igmp_type = 0
        sampling_interval = 0
        sampling_algorithm = 0
        flow_active_timeout = 0
        flow_inactive_timeout = 0
        engine_type = 0
        engine_id = 0
        total_bytes_exp = 0
        total_pkts_exp = 0 
        total_flows_exp = 0
        ipv4_src_prefix = 0
        ipv4_dst_prefix = 0
        mpls_top_label_type = 0
        mpls_top_label_ip_addr = 0
        flow_sampler_id = 0
        flow_sample_mode = 0 
        nterval = 0
        min_ttl = 0
        max_ttl = 0
        ipv4_ident = 0
        dst_tos = 0
        in_src_mac = 0
        out_dst_mac = 0
        src_vlan = 0
        dst_vlan = 0
        ip_protocol_version = 0
        direction = 0
        ipv6_next_hop = 0
        bpg_ipv6_next_hop = 0
        ipv6_option_headers = 0 
        mpls_label_1 = ''
        mpls_label_2 = ''
        mpls_label_3 = ''
        mpls_label_4 = ''
        mpls_label_5 = ''
        mpls_label_6 = ''
        mpls_label_7 = ''
        mpls_label_8 = ''
        mpls_label_9 = ''
        mpls_label_10 = ''
        in_dst_mac = 0
        out_src_mac = 0
        if_name_desc = 0
        sample_name = 0
        in_permanent_bytes = 0
        in_permanent_pkts = 0
        fragment_offset = 0
        forwarding_status = ''

''''
if __name__ == "__main__":
    # We need to save the templates our NetFlow device send over time. Templates
    # are not resended every time a flow is sent to the collector.
    _templates = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print("Listening on interface {}:{}".format(HOST, PORT))

    while 1:
        (data, sender) = sock.recvfrom(8192)
        print("Received data from {}, length {}".format(sender, len(data)))

        export = ExportPacket(data, _templates)
        _templates.update(export.templates)

        print("Processed ExportPacket with {} flows.".format(export.header.count))
        print(export.header.count)
        if len(export.flows) > 0:
                print(export.flows[0].data['L4_DST_PORT'])
        if len(export.flows) > 1:
                print("more than 1 flow received?")
        for flow in export.flows:
                print(export.flows[0].data['L4_SRC_PORT'])
'''''

