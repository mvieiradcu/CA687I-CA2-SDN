import json
import logging

from acl_switch import ACLSwitch
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.lib import dpid as dpid_lib

acl_switch_instance_name = 'acl_switch_api_app'


class ACLSwitchRest(ACLSwitch):

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(ACLSwitchRest, self).__init__(*args, **kwargs)
        self.switches = {}
        wsgi = kwargs['wsgi']
        wsgi.register(ACLSwitchController,
                      {acl_switch_instance_name: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        super(ACLSwitchRest, self).switch_features_handler(ev)
        datapath = ev.msg.datapath
        self.switches[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

    def get_acl_rules(self):
        return super(ACLSwitchRest, self).get_rules()

    def set_acl_rules(self, datapath, proto, new_acl_rules):
        super(ACLSwitchRest, self).set_rules(new_acl_rules)
        super(ACLSwitchRest, self).clear_acl_rules(datapath, proto)


class ACLSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(ACLSwitchController, self).__init__(req, link, data, **config)
        self.acl_switch_app = data[acl_switch_instance_name]
        self.logger = logging.getLogger(__name__)

    @route('aclswitch', '/aclswitch/acl/rules', methods=['POST'])
    def set_acl_rules(self, req, **kwargs):
        acl_rules = json.loads(req.body)
        acl_switch_app = self.acl_switch_app
        datapath = acl_switch_app.datapath

        self.logger.info(f'DATAPATH: {datapath}')
        acl_switch_app.set_acl_rules(datapath, acl_switch_app.proto, acl_rules)
        return Response(status=200)

    @route('aclswitch', '/aclswitch/acl/rules', methods=['GET'])
    def get_acl_rules(self, req, **kwargs):
        acl_rules = self.acl_switch_app.get_acl_rules()
        body = json.dumps(acl_rules)
        return Response(content_type='application/json', body=body)