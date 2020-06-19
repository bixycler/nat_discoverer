import binascii
import logging
import random
import socket
from termcolor import colored
from json import dumps
import argparse
import sys
import time


__version__ = '0.1.0'

log = logging.getLogger('nat.discovery')

STUN_SERVERS = (
    'stun.ekiga.net',
    'stun.ideasip.com',
    'stun.voiparound.com',
    'stun.voipbuster.com',
    'stun.voipstunt.com',
    'stun.voxgratia.org'
)

stun_servers_list = STUN_SERVERS

DEFAULTS = {
    'stun_port': 3478,
    'source_ip': '0.0.0.0',
    'source_port': 54320
}

# stun attributes
MappedAddress = '0001'
ResponseAddress = '0002'
ChangeRequest = '0003'
SourceAddress = '0004'
ChangedAddress = '0005'
Username = '0006'
Password = '0007'
MessageIntegrity = '0008'
ErrorCode = '0009'
UnknownAttribute = '000A'
ReflectedFrom = '000B'
XorOnly = '0021'
XorMappedAddress = '0020'
ServerName = '8022'
SecondaryAddress = '8050'  # Non standard extension

# types for a stun message
BindRequestMsg = '0001'
BindResponseMsg = '0101'
BindErrorResponseMsg = '0111'
SharedSecretRequestMsg = '0002'
SharedSecretResponseMsg = '0102'
SharedSecretErrorResponseMsg = '0112'

dictAttrToVal = {'MappedAddress': MappedAddress,
                 'ResponseAddress': ResponseAddress,
                 'ChangeRequest': ChangeRequest,
                 'SourceAddress': SourceAddress,
                 'ChangedAddress': ChangedAddress,
                 'Username': Username,
                 'Password': Password,
                 'MessageIntegrity': MessageIntegrity,
                 'ErrorCode': ErrorCode,
                 'UnknownAttribute': UnknownAttribute,
                 'ReflectedFrom': ReflectedFrom,
                 'XorOnly': XorOnly,
                 'XorMappedAddress': XorMappedAddress,
                 'ServerName': ServerName,
                 'SecondaryAddress': SecondaryAddress}

dictMsgTypeToVal = {
    'BindRequestMsg': BindRequestMsg,
    'BindResponseMsg': BindResponseMsg,
    'BindErrorResponseMsg': BindErrorResponseMsg,
    'SharedSecretRequestMsg': SharedSecretRequestMsg,
    'SharedSecretResponseMsg': SharedSecretResponseMsg,
    'SharedSecretErrorResponseMsg': SharedSecretErrorResponseMsg}

dictValToMsgType = {}

dictValToAttr = {}

Blocked = "Blocked"
OpenInternet = "Open Internet"
FullCone = "Full Cone"
SymmetricUDPFirewall = "Symmetric UDP Firewall"
RestricNAT = "Restricted Cone"
RestricPortNAT = "Port Restricted Cone"
SymmetricNAT = "Symmetric"
ChangedAddressError = "Meet an error, when do Test1 on Changed IP and Port"


def _initialize():
    items = dictAttrToVal.items()
    for i in range(len(items)):
        dictValToAttr.update({items[i][1]: items[i][0]})
    items = dictMsgTypeToVal.items()
    for i in range(len(items)):
        dictValToMsgType.update({items[i][1]: items[i][0]})


def gen_tran_id():
    a = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
    # return binascii.a2b_hex(a)
    return a


def stun_test(sock, host, port, source_ip, source_port, send_data=""):
    retVal = {'Resp': False, 'ExternalIP': None, 'ExternalPort': None,
              'SourceIP': None, 'SourcePort': None, 'ChangedIP': None,
              'ChangedPort': None}
    str_len = "%#04d" % (len(send_data) / 2)
    tranid = gen_tran_id()
    str_data = ''.join([BindRequestMsg, str_len, tranid, send_data])
    data = binascii.a2b_hex(str_data)
    recvCorr = False
    while not recvCorr:
        recieved = False
        count = 3
        while not recieved:
            log.debug("sendto: %s", (host, port))
            try:
                sock.sendto(data, (host, port))
            except socket.gaierror:
                retVal['Resp'] = False
                return retVal
            try:
                buf, addr = sock.recvfrom(2048)
                buf_hex = binascii.hexlify(buf)
                log.debug(
                    "recvfrom: %s %s", addr,
                    "%s" % buf_hex
                )
                recieved = True
            except Exception as e:
                log.debug("recvfrom: %s %s", host, e)
                recieved = False
                if count > 0:
                    count -= 1
                else:
                    retVal['Resp'] = False
                    return retVal
        msgtype = binascii.b2a_hex(buf[0:2])
        bind_resp_msg = dictValToMsgType[msgtype] == "BindResponseMsg"
        tranid_match = tranid.upper() == binascii.b2a_hex(buf[4:20]).upper()
        if bind_resp_msg and tranid_match:
            recvCorr = True
            retVal['Resp'] = True
            len_message = int(binascii.b2a_hex(buf[2:4]), 16)
            len_remain = len_message
            base = 20
            while len_remain:
                attr_type = binascii.b2a_hex(buf[base:(base + 2)])
                attr_len = int(
                    binascii.b2a_hex(buf[(base + 2):(base + 4)]), 16
                )
                if attr_type == MappedAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(
                            binascii.b2a_hex(buf[base + 8:base + 9]), 16
                        )),
                        str(int(
                            binascii.b2a_hex(buf[base + 9:base + 10]), 16
                        )),
                        str(int(
                            binascii.b2a_hex(buf[base + 10:base + 11]), 16
                        )),
                        str(int(
                            binascii.b2a_hex(buf[base + 11:base + 12]), 16
                        ))
                    ])
                    retVal['ExternalIP'] = ip
                    retVal['ExternalPort'] = port
                if attr_type == SourceAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(
                            binascii.b2a_hex(buf[base + 8:base + 9]), 16
                        )),
                        str(int(
                            binascii.b2a_hex(buf[base + 9:base + 10]), 16
                        )),
                        str(int(
                            binascii.b2a_hex(buf[base + 10:base + 11]), 16
                        )),
                        str(int(
                            binascii.b2a_hex(buf[base + 11:base + 12]), 16
                        ))
                    ])
                    retVal['SourceIP'] = ip
                    retVal['SourcePort'] = port
                if attr_type == ChangedAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(
                            binascii.b2a_hex(buf[base + 8:base + 9]), 16
                        )),
                        str(int(
                            binascii.b2a_hex(buf[base + 9:base + 10]), 16
                        )),
                        str(int(
                            binascii.b2a_hex(buf[base + 10:base + 11]), 16
                        )),
                        str(int(
                            binascii.b2a_hex(buf[base + 11:base + 12]), 16
                        ))
                    ])
                    retVal['ChangedIP'] = ip
                    retVal['ChangedPort'] = port
                # if attr_type == ServerName:
                    # serverName = buf[(base+4):(base+4+attr_len)]
                base = base + 4 + attr_len
                len_remain = len_remain - (4 + attr_len)
    # s.close()
    return retVal


def get_nat_type(s, source_ip, source_port, stun_host=None, stun_port=3478):
    _initialize()
    port = stun_port
    log.debug(colored('# Test I', 'green'))
    resp = False
    if stun_host:
        ret = stun_test(s, stun_host, port, source_ip, source_port)
        resp = ret['Resp']
    else:
        for stun_host in stun_servers_list:
            log.debug('trying STUN host: %s', stun_host)
            ret = stun_test(s, stun_host, port, source_ip, source_port)
            resp = ret['Resp']
            if resp:
                break
    if not resp:
        return Blocked, ret
    log.debug('result: %s', dumps(ret, indent=4))
    exIP = ret['ExternalIP']
    exPort = ret['ExternalPort']
    stunIP = ret['SourceIP']
    changedIP = ret['ChangedIP']
    changedPort = ret['ChangedPort']
    if ret['ExternalIP'] == source_ip:
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        ret = stun_test(s, stunIP, port, source_ip, source_port,
                        changeRequest)
        if ret['Resp']:
            typ = OpenInternet
        else:
            typ = SymmetricUDPFirewall
    else:
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        log.debug(colored('# Test II', 'green'))
        ret = stun_test(s, stunIP, port, source_ip, source_port,
                        changeRequest)
        log.debug('result: %s', dumps(ret, indent=4))
        if ret['Resp']:
            typ = FullCone
        else:
            log.debug(colored('# Test I\'', 'green'))
            ret = stun_test(s, changedIP, port, source_ip, source_port)
            log.debug('result: %s', dumps(ret, indent=4))
            if not ret['Resp']:
                typ = ChangedAddressError
            else:
                if exIP == ret['ExternalIP'] and exPort == ret['ExternalPort']:
                    changePortRequest = ''.join([ChangeRequest, '0004',
                                                 "00000002"])
                    log.debug(colored('# Test III', 'green'))
                    ret = stun_test(s, stunIP, port, source_ip, source_port,
                                    changePortRequest)
                    log.debug('result: %s', dumps(ret, indent=4))
                    if ret['Resp']:
                        typ = RestricNAT
                    else:
                        typ = RestricPortNAT
                else:
                    typ = SymmetricNAT
    return typ, ret


def get_ip_info(source_ip="0.0.0.0", source_port=54320, stun_host=None,
                stun_port=3478):
    socket.setdefaulttimeout(1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind((source_ip, source_port))
    nat_type, nat = get_nat_type(s, source_ip, source_port,
                                 stun_host=stun_host, stun_port=stun_port)
    external_ip = nat['ExternalIP']
    external_port = nat['ExternalPort']
    s.close()
    return (nat_type, external_ip, external_port)

def make_argument_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-d', '--debug', action='store_true',
        help='enable debug logging'
    )
    parser.add_argument(
        '-j', '--json', action='store_true',
        default=False,
        help='JSON output'
    )
    parser.add_argument(
        '-H', '--stun-host',
        help='STUN host to use'
    )
    parser.add_argument(
        '-P', '--stun-port', type=int,
        default=DEFAULTS['stun_port'],
        help='STUN host port to use'
    )
    parser.add_argument(
        '-i', '--source-ip',
        default=DEFAULTS['source_ip'],
        help='network interface for client'
    )
    parser.add_argument(
        '-p', '--source-port', type=int,
        default=DEFAULTS['source_port'],
        help='port to listen on for client'
    )
    parser.add_argument(
        '--version', action='version', version=__version__
    )
    return parser


def main():
    try:
        options = make_argument_parser().parse_args()

        def fprint(msg):
            if not options.json:
                print msg
            return

        logging.basicConfig(format='- %(asctime)-15s %(message)s')
        log.setLevel(
            options.debug and not options.json
            if logging.DEBUG else logging.INFO
        )

        fprint('{}'.format(colored(
            '- Discovering NAT type (it may take 5 to 60 seconds) ...',
            'cyan'
        )))
        nat_type, external_ip, external_port = get_ip_info(
            source_ip=options.source_ip,
            source_port=options.source_port,
            stun_host=options.stun_host,
            stun_port=options.stun_port
        )
        fprint('{}\n'.format('-' * 60))
        fprint(colored('\tNAT Type: {}'.format(nat_type), 'magenta'))
        fprint('\tExternal IP: {}'.format(external_ip))
        fprint('\tExternal Port: {}'.format(external_port))
        fprint('\n{}'.format(('-' * 60)))

        if options.json:
            print dumps({
                'type': nat_type,
                'external_ip': external_ip,
                'external_port': external_port
            }, indent=4)

    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
