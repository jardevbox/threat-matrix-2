#    ------ BEGIN LICENSE ATTRIBUTION ------
#    
#    Portions of this file have been appropriated or derived from the following project(s) and therefore require attribution to the original licenses and authors.
#    
#    Repository: https://github.com/a10networks/a10sdk-python
#    Source File: a10sdk/core/interface/interface_trunk_ip_ospf_ospf_ip.py
#    Licenses:
#      Apache License 2.0
#      SPDXId: Apache-2.0
#    
#    Auto-attribution by Threatrix, Inc.
#    
#    ------ END LICENSE ATTRIBUTION ------
from a10sdk.common.A10BaseClass import A10BaseClass




import io.threatrix.eventsystem.EventManager;
import io.threatrix.eventsystem.events.events.HumanNotificationEvent;
import io.threatrix.eventsystem.subscribers.HumanNotificationEventEmailSubscriber;
import io.threatrix.eventsystem.subscribers.HumanNotificationEventSlackSubscriber;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.Arrays;

@Service
public class HumanNotificationService {

    @Autowired
    private EventManager eventManager;
    @Autowired
    private HumanNotificationEventEmailSubscriber emailSubscriber;
    @Autowired
    private HumanNotificationEventSlackSubscriber slackSubscriber;

    @PostConstruct
    private void init() {
        eventManager.subscribe(HumanNotificationEvent.class, emailSubscriber);
        eventManager.subscribe(HumanNotificationEvent.class, slackSubscriber);
    }


    public void sendNotification(String message) {
        eventManager.publish(new HumanNotificationEvent(message));
    }

    public void sendNotification(Class clazz, Exception e) {
        eventManager.publish(new HumanNotificationEvent("Exception at " + clazz.getName() + ": " + e.getMessage() + "\n" + Arrays.toString(e.getStackTrace())));
    }

class MessageDigestCfg(A10BaseClass):
    
    """This class does not support CRUD Operations please use parent.

    :param md5_value: {"minLength": 1, "maxLength": 16, "type": "string", "description": "The OSPF password (1-16)", "format": "password"}
    :param message_digest_key: {"description": "Message digest authentication password (key) (Key id)", "minimum": 1, "type": "number", "maximum": 255, "format": "number"}
    :param encrypted: {"type": "encrypted", "description": "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)", "format": "encrypted"}
    :param DeviceProxy: The device proxy for REST operations and session handling. Refer to `common/device_proxy.py`

    

    
    """
    def __init__(self, **kwargs):
        self.ERROR_MSG = ""
        
        self.b_key = "message-digest-cfg"
        self.DeviceProxy = ""
        self.md5_value = ""
        self.message_digest_key = ""
        self.encrypted = ""

        for keys, value in kwargs.items():
            setattr(self,keys, value)


class OspfIp(A10BaseClass):
    
    """Class Description::
    IP address configuration for Open Shortest Path First for IPv4 (OSPF).

    Class ospf-ip supports CRUD Operations and inherits from `common/A10BaseClass`.
    This class is the `"PARENT"` class for this module.`

    :param dead_interval: {"description": "Interval after which a neighbor is declared dead (Seconds)", "format": "number", "default": 40, "optional": true, "maximum": 65535, "minimum": 1, "type": "number"}
    :param authentication_key: {"description": "Authentication password (key) (The OSPF password (key))", "format": "string-rlx", "minLength": 1, "optional": true, "maxLength": 8, "type": "string"}
    :param uuid: {"description": "uuid of the object", "format": "string", "minLength": 1, "modify-not-allowed": 1, "optional": true, "maxLength": 64, "type": "string"}
    :param mtu_ignore: {"default": 0, "optional": true, "type": "number", "description": "Ignores the MTU in DBD packets", "format": "flag"}
    :param priority: {"description": "Router priority", "format": "number", "default": 1, "optional": true, "maximum": 255, "minimum": 0, "type": "number"}
    :param transmit_delay: {"description": "Link state transmit delay (Seconds)", "format": "number", "default": 1, "optional": true, "maximum": 65535, "minimum": 1, "type": "number"}
    :param value: {"optional": true, "enum": ["message-digest", "null"], "type": "string", "description": "'message-digest': Use message-digest authentication; 'null': Use no authentication; ", "format": "enum"}
    :param hello_interval: {"description": "Time between HELLO packets (Seconds)", "format": "number", "default": 10, "optional": true, "maximum": 65535, "minimum": 1, "type": "number"}
    :param authentication: {"default": 0, "optional": true, "type": "number", "description": "Enable authentication", "format": "flag"}
    :param cost: {"description": "Interface cost", "format": "number", "type": "number", "maximum": 65535, "minimum": 1, "optional": true}
    :param database_filter: {"optional": true, "enum": ["all"], "type": "string", "description": "'all': Filter all LSA; ", "format": "enum"}
    :param ip_addr: {"optional": false, "type": "string", "description": "Address of interface", "format": "ipv4-address"}
    :param retransmit_interval: {"description": "Time between retransmitting lost link state advertisements (Seconds)", "format": "number", "default": 5, "optional": true, "maximum": 65535, "minimum": 1, "type": "number"}
    :param message_digest_cfg: {"minItems": 1, "items": {"type": "object"}, "uniqueItems": true, "type": "array", "array": [{"properties": {"md5-value": {"minLength": 1, "maxLength": 16, "type": "string", "description": "The OSPF password (1-16)", "format": "password"}, "message-digest-key": {"description": "Message digest authentication password (key) (Key id)", "minimum": 1, "type": "number", "maximum": 255, "format": "number"}, "optional": true, "encrypted": {"type": "encrypted", "description": "Do NOT use this option manually. (This is an A10 reserved keyword.) (The ENCRYPTED password string)", "format": "encrypted"}}}]}
    :param out: {"default": 0, "optional": true, "type": "number", "description": "Outgoing LSA", "format": "flag"}
    :param DeviceProxy: The device proxy for REST operations and session handling. Refer to `common/device_proxy.py`

    

    URL for this object::
    `https://<Hostname|Ip address>//axapi/v3/interface/trunk/{ifnum}/ip/ospf/ospf-ip/{ip_addr}`.

    

    
    """
    def __init__(self, **kwargs):
        self.ERROR_MSG = ""
        self.required = [ "ip_addr"]

        self.b_key = "ospf-ip"
        self.a10_url="/axapi/v3/interface/trunk/{ifnum}/ip/ospf/ospf-ip/{ip_addr}"
        self.DeviceProxy = ""
        self.dead_interval = ""
        self.authentication_key = ""
        self.uuid = ""
        self.mtu_ignore = ""
        self.priority = ""
        self.transmit_delay = ""
        self.value = ""
        self.hello_interval = ""
        self.authentication = ""
        self.cost = ""
        self.database_filter = ""
        self.ip_addr = ""
        self.retransmit_interval = ""
        self.message_digest_cfg = []
        self.out = ""

        for keys, value in kwargs.items():
            setattr(self,keys, value)


