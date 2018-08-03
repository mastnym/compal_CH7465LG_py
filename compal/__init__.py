"""
Client for the Compal CH7465LG/Ziggo Connect box cable modem
"""
import io
import logging
import urllib

from xml.dom import minidom
from enum import Enum
from collections import OrderedDict

import requests

from .functions import Set, Get

LOGGER = logging.getLogger(__name__)
logging.basicConfig()

LOGGER.setLevel(logging.INFO)


class NatMode(Enum):
    """
    Values for NAT-Mode
    """
    enabled = 1
    disabled = 2


class Compal(object):
    """
    Basic functionality for the router's API
    """
    def __init__(self, router_ip, key=None, timeout=10):
        self.router_ip = router_ip
        self.timeout = timeout
        self.key = key

        self.session = requests.Session()
        # limit the number of redirects
        self.session.max_redirects = 3

        # after a response is received, process the token field of the response
        self.session.hooks['response'].append(self.token_handler)
        # session token is initially empty
        self.session_token = None

        LOGGER.debug("Getting initial token")
        # check the initial URL. If it is redirected, perform the initial
        # installation
        self.initial_res = self.get('/')

        if self.initial_res.url.endswith('common_page/FirstInstallation.html'):
            self.initial_setup()
        elif not self.initial_res.url.endswith('common_page/login.html'):
            LOGGER.error("Was not redirected to login page:"
                         " concurrent session?")

    def initial_setup(self, new_key=None):
        """
        Replay the settings made during initial setup
        """
        LOGGER.info("Initial setup: english.")

        if new_key:
            self.key = new_key

        if not self.key:
            raise ValueError("No key/password availalbe")

        self.xml_getter(Get.MULTILANG, {})
        self.xml_getter(Get.LANGSETLIST, {})
        self.xml_getter(Get.MULTILANG, {})

        self.xml_setter(Set.LANGUAGE, {'lang': 'en'})
        # Login or change password? Not sure.
        self.xml_setter(Set.LOGIN, OrderedDict([
            ('Username', 'admin'),
            ('Password', self.key)
        ]))
        # Get current wifi settings (?)
        self.xml_getter(Get.WIRELESSBASIC, {})

        # Some sheets with hints, no request
        # installation is done:
        self.xml_setter(Set.INSTALL_DONE, {
            'install': 0,
            'iv': 1,
            'en': 0
        })

    def url(self, path):
        """
        Calculate the absolute URL for the request
        """
        while path.startswith('/'):
            path = path[1:]

        return "http://{ip}/{path}".format(ip=self.router_ip, path=path)

    def token_handler(self, res, *args, **kwargs):
        """
        Handle the anti-replace token system
        """
        self.session_token = res.cookies.get('sessionToken')

        if res.status_code == 302:
            LOGGER.info("302 [%s] => '%s' [token: %s]", res.url,
                        res.headers['Location'], self.session_token)
        else:
            LOGGER.debug("%s [%s] [token: %s]", res.status_code, res.url,
                         self.session_token)

    def post(self, path, _data, **kwargs):
        """
        Prepare and send a POST request to the router

        Wraps `requests.get` and sets the 'token' and 'fun' fields at the
        correct position in the post data.

        **The router is sensitive to the ordering of the fields**
        (Which is a code smell)
        """
        data = OrderedDict()
        data['token'] = self.session_token

        if 'fun' in _data:
            data['fun'] = _data.pop('fun')

        data.update(_data)

        LOGGER.debug("POST [%s]: %s", path, data)

        res = self.session.post(self.url(path), data=data,
                                allow_redirects=False, timeout=self.timeout,
                                **kwargs)

        return res

    def post_binary(self, path, binary_data, filename, **kwargs):
        """
        Perform a post request with a file as form-data in it's body.
        """

        headers = {
            'Content-Disposition':
                'form-data; name="file"; filename="%s"' % filename,  # noqa
            'Content-Type': 'application/octet-stream'
        }
        self.session.post(self.url(path), data=binary_data, headers=headers,
                          **kwargs)

    def get(self, path, **kwargs):
        """
        Perform a GET request to the router

        Wraps `requests.get` and sets the required referer.
        """
        res = self.session.get(self.url(path), timeout=self.timeout, **kwargs)

        self.session.headers.update({'Referer': res.url})
        return res

    def xml_getter(self, fun, params):
        """
        Call `/xml/getter.xml` for the given function and parameters
        """
        params['fun'] = fun

        return self.post('/xml/getter.xml', params)

    def xml_setter(self, fun, params=None):
        """
        Call `/xml/setter.xml` for the given function and parameters.
        The params are optional
        """
        params['fun'] = fun

        return self.post('/xml/setter.xml', params)

    def login(self, key=None):
        """
        Login. Allow this function to override the key.
        """

        res = self.xml_setter(Set.LOGIN, OrderedDict([
            ('Username', 'admin'),
            ('Password', key if key else self.key)
        ]))

        if res.status_code != 200:
            if res.headers['Location'].endswith(
                    'common_page/Access-denied.html'):
                raise ValueError('Access denied. '
                                 'Still logged in somewhere else?')
            else:
                raise ValueError('Login failed for unknown reason!')

        tokens = urllib.parse.parse_qs(res.text)

        token_sids = tokens.get('SID')
        if not token_sids:
            raise ValueError('No valid session-Id received! Wrong password?')

        token_sid = token_sids[0]
        LOGGER.info("[login] SID %s", token_sid)

        self.session.cookies.update({'SID': token_sid})

        return res

    def reboot(self):
        """
        Reboot the router
        """
        try:
            LOGGER.info("Performing a reboot - this will take a while")
            return self.xml_setter(Set.REBOOT, {})
        except requests.exceptions.ReadTimeout:
            return None

    def factory_reset(self):
        """
        Perform a factory reset
        """
        default_settings = self.xml_getter(Get.DEFAULTVALUE, {})

        try:
            LOGGER.info("Initiating factory reset - this will take a while")
            self.xml_setter(Set.FACTORY_RESET, {})
        except requests.exceptions.ReadTimeout:
            pass
        return default_settings

    def logout(self):
        """
        Logout of the router. This is required since only a single session can
        be active at any point in time.
        """
        return self.xml_setter(Set.LOGOUT, {})

    def set_modem_mode(self):
        """
        Sets router to Modem-mode
        After setting this, router will not be reachable by IP!
        It needs factory reset to function as a router again!
        """
        return self.xml_setter(Set.NAT_MODE, {'NAT': NatMode.enabled.value})

    def change_password(self, old_password, new_password):
        """
        Change the admin password
        """
        return self.xml_setter(Set.CHANGE_PASSWORD, OrderedDict([
            ('oldpassword', old_password),
            ('newpassword', new_password)
        ]))


class Proto(Enum):
    """
    protocol (from form): 1 = tcp, 2 = udp, 3 = both
    """
    tcp = 1
    udp = 2
    both = 3


class FilterAction(Enum):
    """
    Filter action, used by internet access filters
    """
    add = 1
    delete = 2
    enable = 3


class TimerMode(Enum):
    """
    Timermodes used for internet access filtering
    """
    generaltime = 1
    dailytime = 2


class Filters(object):
    """
    Provide filters for accessing the internet.

    Supports access-restriction via parental control (Keywords, url-lists,
    timetable), client's MAC address and by specific ports.
    """

    def __init__(self, modem):
        self.modem = modem

    def set_parental_control(self, safe_search, keyword_list, allow_list,
                             deny_list, timer_mode, enable):
        """
        Filter internet access by keywords or block/allow whole urls
        Allowed times can be set too
        """
        data = "EN=%s;" % ("1" if enable else "2")
        data += "SAFE=%s;" % ("1" if safe_search else "2")

        data += "KEY=%s;" % ("1" if len(keyword_list) else "0")
        data += "KEYLIST="
        if len(keyword_list):
            data += ",".join(keyword_list) + ";"
        else:
            data += "empty" + ";"

        data += "ALLOW=%s;" % ("1" if len(allow_list) else "0")
        data += "ALLOWLIST="
        if len(keyword_list):
            data += ",".join(keyword_list) + ";"
        else:
            data += "empty" + ";"

        data += "DENY=%s;" % ("1" if len(deny_list) else "0")
        data += "DENYLIST="
        if len(keyword_list):
            data += ",".join(keyword_list) + ";"
        else:
            data += "empty" + ";"

        if TimerMode.generaltime == timer_mode:
            timer_rule = "0,0"
        elif TimerMode.dailytime == timer_mode:
            timer_rule = "0,0"
        else:
            timer_rule = "empty"

        data += "TMODE=%i;" % timer_mode.value
        data += "TIMERULE=%s;" % timer_rule

        self.modem.xml_setter(Set.PARENTAL_CONTROL, {'data': data})

    def set_mac_filter(self, action, device_name, mac_addr, timer_mode,
                       enable):
        """
        Restrict access to the internet via client MAC address
        """
        if FilterAction.add == action:
            data = "ADD,"
        elif FilterAction.delete == action:
            data = "DEL,"
        elif FilterAction.enable == action:
            data = "EN,"
        else:
            LOGGER.error("No action supplied for MAC filter rule")
            return

        data += device_name + ","
        data += mac_addr + ","
        data += "%i" % (1 if enable else 2) + ";"

        if TimerMode.generaltime == timer_mode:
            timerule = "0,0"
        elif TimerMode.dailytime == timer_mode:
            timerule = "0,0"
        else:
            timerule = "0"

        data += "MODE=%i," % timer_mode.value
        data += "TIME=%s;" % timerule

        return self.modem.xml_setter(Set.MACFILTER, {'data': data})

    def set_ipv6_filter_rule(self):
        """
        To be integrated...
        """
        params = OrderedDict([
            ('act', ''),
            ('dir', ''),
            ('enabled', ''),
            ('allow_traffic', ''),
            ('protocol', ''),
            ('src_addr', ''),
            ('src_prefix', ''),
            ('dst_addr', ''),
            ('dst_prefix', ''),
            ('ssport', ''),
            ('seport', ''),
            ('dsport', ''),
            ('deport', ''),
            ('del', ''),
            ('idd', ''),
            ('sIpRange', ''),
            ('dsIpRange', ''),
            ('PortRange', ''),
            ('TMode', ''),
            ('TRule', '')
        ])
        return self.modem.xml_setter(Set.IPV6_FILTER_RULE, params)

    def set_filter_rule(self):
        """
        To be integrated...
        """
        params = OrderedDict([
            ('act', ''),
            ('enabled', ''),
            ('protocol', ''),
            ('src_addr_s', ''),
            ('src_addr_e', ''),
            ('dst_addr_s', ''),
            ('dst_addr_e', ''),
            ('ssport', ''),
            ('seport', ''),
            ('dsport', ''),
            ('deport', ''),
            ('del', ''),
            ('idd', ''),
            ('sIpRange', ''),
            ('dsIpRange', ''),
            ('PortRange', ''),
            ('TMode', ''),
            ('TRule', '')
        ])
        return self.modem.xml_setter(Set.FILTER_RULE, params)





class DHCPSettings(object):
    """
    Confgure the DHCP settings
    """
    def __init__(self, modem):
        self.modem = modem

    def add_static_lease(self, lease_ip, lease_mac):
        """
        Add a static DHCP lease
        """
        return self.modem.xml_setter(Set.STATIC_DHCP_LEASE, {
            'data': 'ADD,{ip},{mac};'.format(ip=lease_ip, mac=lease_mac)
        })

    def set_upnp_status(self, enabled):
        """
        Ensure that UPnP is set to the given value
        """
        return self.modem.xml_setter(Set.UPNP_STATUS, OrderedDict([
            ('LanIP', ''),
            ('UPnP', 1 if enabled else 2),
            ('DHCP_addr_s', ''), ('DHCP_addr_e', ''),
            ('subnet_Mask', ''),
            ('DMZ', ''), ('DMZenable', '')
        ]))

    # Changes Router IP too, according to given range
    def set_ipv4_dhcp(self, addr_start, addr_end, num_devices, lease_time,
                      enabled):
        """
        Change the DHCP range. This implies a change to the router IP
        **check**: The router takes the first IP in the given range
        """
        return self.modem.xml_setter(Set.DHCP_V4, OrderedDict([
            ('action', 1),
            ('addr_start_s', addr_start), ('addr_end_s', addr_end),
            ('numberOfCpes_s', num_devices),
            ('leaseTime_s', lease_time),
            ('mac_addr', ''),
            ('reserved_addr', ''),
            ('_del', ''),
            ('enable', 1 if enabled else 2)
        ]))

    def set_ipv6_dhcp(self, autoconf_type, addr_start, addr_end, num_addrs,
                      vlifetime, ra_lifetime, ra_interval, radvd, dhcpv6):
        """
        Configure IPv6 DHCP settings
        """
        return self.modem.xml_setter(Set.DHCP_V6, OrderedDict([
            ('v6type', autoconf_type),
            ('Addr_start', addr_start),
            ('NumberOfAddrs', num_addrs),
            ('vliftime', vlifetime),
            ('ra_lifetime', ra_lifetime),
            ('ra_interval', ra_interval),
            ('radvd', radvd),
            ('dhcpv6', dhcpv6),
            ('Addr_end', addr_end)
        ]))


class MiscSettings(object):
    """
    Miscellanious settings
    """
    def __init__(self, modem):
        self.modem = modem

    def set_mtu(self, mtu_size):
        """
        Sets the MTU
        """
        return self.modem.xml_setter(Set.MTU_SIZE, {
            'MTUSize': mtu_size
        })

    def set_remoteaccess(self, enabled, port=8443):
        """
        Ensure that remote access is enabled/disabled on the given port
        """
        return self.modem.xml_setter(Set.REMOTE_ACCESS, OrderedDict([
            ('RemoteAccess', 1 if enabled else 2),
            ('Port', port)
        ]))

    def set_forgot_pw_email(self, email_addr):
        """
        Set email address for Forgot Password function
        """
        return self.modem.xml_setter(Set.SET_EMAIL, OrderedDict([
            ('email', email_addr),
            ('emailLen', len(email_addr)),
            ('opt', 0)
        ]))

    def send_forgot_pw_email(self, email_addr):
        """
        Send an email to receive new or forgotten password
        """
        return self.modem.xml_setter(Set.SEND_EMAIL, OrderedDict([
            ('email', email_addr),
            ('emailLen', len(email_addr)),
            ('opt', 0)
        ]))


class DiagToolName(Enum):
    """
    Enumeration of diagnostic tool names
    """
    ping = "ping"
    traceroute = "traceroute"


class Diagnostics(object):
    """
    Diagnostic functions
    """
    def __init__(self, modem):
        self.modem = modem

    def start_pingtest(self, target_addr, ping_size=64, num_ping=3,
                       interval=10):
        """
        Start Ping-Test
        """
        return self.modem.xml_setter(Set.PING_TEST, OrderedDict([
            ('Type', 1),
            ('Target_IP', target_addr),
            ('Ping_Size', ping_size),
            ('Num_Ping', num_ping),
            ('Ping_Interval', interval)
        ]))

    def stop_pingtest(self):
        """
        Stop Ping-Test
        """
        return self.modem.xml_setter(Set.STOP_DIAGNOSTIC, {
            'Ping': DiagToolName.ping
        })

    def get_pingtest_result(self):
        """
        Get Ping-Test results
        """
        return self.modem.xml_getter(Get.PING_RESULT, {})

    def start_traceroute(self, target_addr, max_hops, data_size, base_port,
                         resolve_host):
        """
        Start Traceroute
        """
        return self.modem.xml_setter(Set.TRACEROUTE, OrderedDict([
            ('type', 1),
            ('Tracert_IP', target_addr),
            ('MaxHops', max_hops),
            ('DataSize', data_size),
            ('BasePort', base_port),
            ('ResolveHost', 1 if resolve_host else 0)
        ]))

    def stop_traceroute(self):
        """
        Stop Traceroute
        """
        return self.modem.xml_setter(Set.STOP_DIAGNOSTIC, {
            'Traceroute': DiagToolName.traceroute
        })

    def get_traceroute_result(self):
        """
        Get Traceroute results
        """
        return self.modem.xml_getter(Get.TRACEROUTE_RESULT, {})




class LanTable:
    ETHERNET = "Ethernet"
    WIFI = "WIFI"
    TOTAL = 'totalClient'

    def __init__(self, modem):
        self.modem = modem
        self.table = None
        self.refresh()

    def _parse_lan_table_xml(self, dom):
        table = {LanTable.ETHERNET: [], LanTable.WIFI: []}
        for con_type in table.keys():
            con_node = dom.getElementsByTagName(con_type)[0]
            for client in con_node.childNodes:
                client_info = {}
                for prop in client.childNodes:
                    client_info[prop.tagName] = prop.firstChild.nodeValue
                table[con_type].append(client_info)
        table[LanTable.TOTAL] = dom.getElementsByTagName(LanTable.TOTAL)[0].firstChild.nodeValue
        self.table = table

    def _check_data(self):
        if self.table is None:
            self.refresh()

    def refresh(self):
        resp = self.modem.xml_getter(Get.LANUSERTABLE, {})
        if resp.status_code != 200:
            LOGGER.error("Didn't receive correct response, try to call LanTable.refresh()")
            return
        dom = minidom.parseString(resp.content)
        self._parse_lan_table_xml(dom)

    def get_lan(self):
        self._check_data()
        return self.table.get(LanTable.ETHERNET)

    def get_wifi(self):
        self._check_data()
        return self.table.get(LanTable.WIFI)

    def get_client_count(self):
        self._check_data()
        return self.table.get(LanTable.TOTAL)

# How to use?
# modem = Compal('192.168.178.1', '1234567')
# modem.login()
# Or provide key on login:
# modem.login('1234567')
# fw = PortForwards(modem)
# print(list(fw.rules))
