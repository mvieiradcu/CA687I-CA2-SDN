from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ipv4, packet, tcp, in_proto, ethernet, ether_types
from ryu.ofproto import ofproto_v1_3


class ACLSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ACLSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.acl_rules = [

        ]
        self.datapath = None
        self.proto = None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.datapath = ev.msg.datapath

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto

        self.proto = ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 1, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        self.logger.info(
            f'add_flow: datapath: {datapath} - priority: {priority} - match: {match} - actions: {actions} ')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=0, hard_timeout=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # self.logger.info(f'\n----> START METHOD PACKET_IN_HANDLER -------------- ')

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:

                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                protocol = ip_pkt.proto

                str_protocol = 'TCP'
                # IF ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    str_protocol = 'ICMP'
                #  IF UDP Protocol
                elif protocol == in_proto.IPPROTO_UDP:
                    str_protocol = 'UDP'

                self.logger.info(
                    f'\n************ Handling {str_protocol} Packets From SRC_IP: {src_ip} To DST_IP: {dst_ip} ***********************************************')

                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=src_ip,
                                        ipv4_dst=dst_ip,
                                        ip_proto=protocol)

                if not self.is_allowed(match):
                    self.logger.info(f'             Result: PACKET NOT ALLOWED')
                    actions = []
                else:
                    self.logger.info(f'             Result: ALLOWED')

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,

                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.info(
            f'************ FINISH METHOD PACKET_IN_HANDLER IP: ***************************************************************************\n')

    def is_allowed(self, match):
        self.logger.info(f'             Match: {match}')
        # Check if the packet matches an ACL rule

        if not self.acl_rules:
            self.logger.info("             NO RULE FOUND.")
            return True

        for rule in self.acl_rules:

            if match.get('ipv4_src') == rule['src_ip'] and match.get('ipv4_dst') == rule['dst_ip']:

                if in_proto.IPPROTO_ICMP == match.get('ip_proto') and 'false' == rule.get('allow_icmp', 'true'):
                    self.logger.info(f'             ACL RULE: {rule} ')
                    return False

                allow = rule['action'] == 'allow'
                rule_protocol = rule.get('protocol')

                if allow and rule_protocol == '*':
                    continue

                if not allow and rule_protocol == '*':
                    self.logger.info(f'             ACL RULE: {rule}')
                    return False

                if not allow and rule_protocol == 'UDP' and (match.get('ip_proto') == in_proto.IPPROTO_UDP):
                    self.logger.info(f'             ACL RULE: {rule}')
                    return False

                if not allow and rule_protocol == 'TCP' and (match.get('ip_proto') == in_proto.IPPROTO_TCP):
                    self.logger.info(f'             ACL RULE: {rule}')
                    return False

        # self.logger.info("             NO RULE FOUND.")
        # If no rule matches, allow the packet
        return True

    def get_rules(self):
        return self.acl_rules

    def set_rules(self, new_acl_rules):
        self.acl_rules = new_acl_rules

    def clear_acl_rules(self, datapath, ofproto):
        """
           Set the ACL rules for the switch
           """
        parser = datapath.ofproto_parser

        # Create flows for each ACL rule
        for rule in self.acl_rules:
            # Create a match that matches the source and destination IP addresses
            match = parser.OFPMatch(
                eth_type=0x0800,  # IPv4
                ipv4_src=rule['src_ip'],
                ipv4_dst=rule['dst_ip']
            )

            # Create an action list based on the rule action
            if rule['action'] == 'allow':
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            elif rule['action'] == 'deny':
                actions = []
            else:
                raise ValueError(f"Invalid action: {rule['action']}")

            # # If the rule allows ICMP, add a match for ICMP packets and append an
            # # action to allow ICMP packets
            # if rule.get('allow_icmp', False):
            #     self.logger.info(f'allow_icmp. {match}')
            #
            #     match.append_field(
            #         'ip_proto', ipv4.inet.IPPROTO_ICMP
            #     )
            #     actions.append(parser.OFPActionOutput(ofproto.OFPP_NORMAL))

            # Create an instruction list based on the actions
            instructions = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )]

            # Create a flow mod message with the add command
            mod = parser.OFPFlowMod(
                datapath=self.datapath,
                priority=0,
                match=match,
                instructions=instructions,
                table_id=0,
                idle_timeout=0,
                hard_timeout=0,
                command=ofproto.OFPFC_ADD
            )

            # Send the flow mod message to the switch
            self.datapath.send_msg(mod)
