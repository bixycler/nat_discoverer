import binascii
import struct
import logging
import random
import socket
from json import dumps
import argparse


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
    'source_port': 0
}

# STUN attributes
STUN_ATTR_NAME = {
    #RFC3489
    '0001': 'MAPPED-ADDRESS',
    '0002': 'RESPONSE-ADDRESS',
    '0003': 'CHANGE-REQUEST',
    '0004': 'SOURCE-ADDRESS',
    '0005': 'CHANGED-ADDRESS',
    '0006': 'USERNAME',
    '0007': 'PASSWORD',
    '0008': 'MESSAGE-INTEGRITY',
    '0009': 'ERROR-CODE',
    '000a': 'UNKNOWN-ATTRIBUTES',
    '000b': 'REFLECTED-FROM',
    #RFC5389
    '0020': 'XOR-MAPPED-ADDRESS',
    '8022': 'SOFTWARE',
    '8023': 'ALTERNATE-SERVER',
    '8028': 'FINGERPRINT',
    #RFC5780
    '0026': 'PADDING',
    '0027': 'RESPONSE-PORT',
    '802b': 'RESPONSE-ORIGIN',
    '802c': 'OTHER-ADDRESS'
}

# STUN message types
STUN_MSG_NAME = { #RFC3489
    '0001': 'Binding Request',
    '0101': 'Binding Response',
    '0111': 'Binding Error Response',
    '0002': 'Shared Secret Request',
    '0102': 'Shared Secret Response',
    '0112': 'Shared Secret Error Response'
}

def changeRequest(chIP=False, chPort=False):
    b = ((chIP==True)*2 + (chPort==True))*2
    a = binascii.b2a_hex(struct.pack('B',b))
    return ''.join([STUN_ATTR['CHANGE-REQUEST'], '0004', '000000',a])

# Connection & NAT types
Blocked = "(Blocked)"
TestingError = "(Error testing for NAT discovery)"
OpenInternet = "Open Internet (no NAT)"
FullCone = "Full Cone"
SymmetricUDPFirewall = "Symmetric UDP Firewall"
RestricNAT = "Restricted Cone"
RestricPortNAT = "Port Restricted Cone"
SymmetricNAT = "Symmetric"
EndpointIndependent = 'Endpoint Independent'
AddressDependent = 'Address Dependent'
PortDependent = 'Port Dependent'
AddressPortDependent = 'Address-Port Dependent'

def inverseDict(d):
    items = d.items()
    rd = {}
    for i in range(len(items)):
        rd.update({items[i][1]: items[i][0]})
    return rd

STUN_MSG = inverseDict(STUN_MSG_NAME)
STUN_ATTR = inverseDict(STUN_ATTR_NAME)

def gen_tran_id(classic=False):
    m = '' if classic else '2112a442'
    a = ''.join(random.choice('0123456789abcdef') for i in range(32-len(m)))
    return m + a

def parseAddress(buf):
    port = struct.unpack('!H', buf[:2])[0]
    ip = ".".join([
        str(struct.unpack('!B', buf[2:3])[0]),
        str(struct.unpack('!B', buf[3:4])[0]),
        str(struct.unpack('!B', buf[4:5])[0]),
        str(struct.unpack('!B', buf[5:6])[0])
    ])
    return ip, port

def stun_test(sock, host, port, send_data="", classic=False):
    ret = {'Err': None, 
        'ExternalIP': None, 'ExternalPort': None,
        'ResponseIP': None, 'ResponsePort': None, 
        'OtherIP': None, 'OtherPort': None}
    str_len = "%#04d" % (len(send_data) / 2)
    tranid = gen_tran_id(classic)
    str_data = ''.join([STUN_MSG['Binding Request'], str_len, tranid, send_data])
    data = binascii.a2b_hex(str_data)
    recvCorr = False
    while not recvCorr:
        recieved = False
        count = 2
        while not recieved:
            log.debug("sendto: %s", (host, port))
            try:
                sock.sendto(data, (host, port))
            except socket.gaierror:
                ret['Err'] = 'Socket Error'
                return ret
            try:
                buf, addr = sock.recvfrom(2048)
                buf_hex = binascii.b2a_hex(buf)
                log.debug("recvfrom: %s %s", addr, buf_hex)
                recieved = True
            except Exception as e:
                log.debug("recvfrom: %s %s", host, e)
                recieved = False
                if count > 1: count -= 1
                else: 
                    ret['Err'] = 'Timeout'
                    return ret

        #STUN header (20 bytes)
        msgtype = binascii.b2a_hex(buf[0:2])
        if msgtype != STUN_MSG["Binding Response"]:
            log.debug("Received message from STUN server: %s %s", 
                STUN_MSG_NAME[msgtype], binascii.b2a_hex(buf))
            ret['Err'] = 'Not a Binding Response'
            return ret
        rtranid = binascii.b2a_hex(buf[4:20])
        if tranid != rtranid:
            log.debug("Transaction ID mismatch: %s != %s", tranid,rtranid)
            ret['Err'] = 'Transaction ID Mismatch'
            return ret
        recvCorr = True
        len_message = struct.unpack('!H', buf[2:4])[0]
        len_remain = len_message

        #STUN attributes
        base = 20
        while len_remain:
            attr_type = binascii.b2a_hex(buf[base:(base+2)])
            attr_len = struct.unpack('!H', buf[(base+2):(base+4)])[0]
            if attr_type == STUN_ATTR['MAPPED-ADDRESS']:
                ret['ExternalIP'], ret['ExternalPort'] = parseAddress(buf[base+6:])
            elif ( attr_type == STUN_ATTR['RESPONSE-ORIGIN'] 
                or attr_type == STUN_ATTR['SOURCE-ADDRESS'] ):
                ret['ResponseIP'], ret['ResponsePort'] = parseAddress(buf[base+6:])
            elif ( attr_type == STUN_ATTR['OTHER-ADDRESS']
                or attr_type == STUN_ATTR['CHANGED-ADDRESS'] ):
                ret['OtherIP'], ret['OtherPort'] = parseAddress(buf[base+6:])
            l = 4 + attr_len
            if attr_len%4 != 0: l += 4 - (attr_len%4)
            base += l; len_remain -= l
    return ret

def open_socket(source_ip, source_port):
    socket.setdefaulttimeout(3)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind((source_ip, source_port))
    return s

# RFC3489: Simple Traversal of UDP Through NATs (in section 10. Use Cases)
def check_nat_type(source_ip='0.0.0.0', source_port=0, stun_host=None, stun_port=3478):
    s = open_socket(source_ip, source_port)

    # Test I: Send regular Binding Request
    log.debug('# Test I: Send regular Binding Request')
    err = True
    if stun_host:
        ret = stun_test(s, stun_host, stun_port, classic=True)
        err = ret['Err']
    else:
        for stun_host in stun_servers_list:
            log.debug('trying STUN host: %s', stun_host)
            ret = stun_test(s, stun_host, stun_port, classic=True)
            err = ret['Err']
            if not err: break
    if err: s.close(); return Blocked, None, None
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    exIP = ret['ExternalIP']
    exPort = ret['ExternalPort']
    stunIP = ret['ResponseIP']
    changedIP = ret['OtherIP']
    changedPort = ret['OtherPort']
    if ret['ExternalIP'] == source_ip:
        # Test II: Request to change both IP and port
        log.debug('# Test II: Request to change both IP and port')
        ret = stun_test(s, stunIP, stun_port, 
            changeRequest(True,True), classic=True)
        log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
        if not ret['Err']: s.close(); return OpenInternet, exIP,exPort
        elif ret['Err'] == 'Timeout': s.close(); return SymmetricUDPFirewall, exIP,exPort
        else: return TestingError, exIP,exPort

    # Test II: Request to change both IP and port
    log.debug('# Test II: Request to change both IP and port')
    ret = stun_test(s, stunIP, stun_port, changeRequest(True,True), classic=True)
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    if not ret['Err']: s.close(); return FullCone, exIP,exPort
    elif ret['Err'] != 'Timeout': s.close(); return TestingError, exIP,exPort

    # Test I': Send regular Binding Request to the other address
    log.debug("# Test I': Send regular Binding Request to the other address")
    ret = stun_test(s, changedIP, changedPort, classic=True)
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    if ret['Err']: s.close(); return TestingError, exIP,exPort
    elif exIP != ret['ExternalIP'] or exPort != ret['ExternalPort']:
        s.close(); return SymmetricNAT, exIP,exPort

    # Test III: Request to change port only
    s.close(); s = open_socket(source_ip, source_port) #reinit to clear previous state
    log.debug('# Test III: Request to change port only')
    ret = stun_test(s, stunIP, stun_port, changeRequest(chPort=True), classic=True)
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    if not ret['Err']: s.close(); return RestricNAT, exIP,exPort
    elif ret['Err'] == 'Timeout': 
        s.close(); return RestricPortNAT, exIP,exPort
    else: return TestingError, exIP,exPort

# RFC5780: 4.3.+  Determining NAT Mapping Behavior (4 types)
def check_mapping_type(source_ip='0.0.0.0', source_port=0, stun_host=None, stun_port=3478):
    s = open_socket(source_ip, source_port)

    # Test I: Send regular Binding Request
    log.debug('# Test I: Send regular Binding Request')
    err = True
    if stun_host:
        ret = stun_test(s, stun_host, stun_port)
        err = ret['Err']
    else:
        for stun_host in stun_servers_list:
            log.debug('trying STUN host: %s', stun_host)
            ret = stun_test(s, stun_host, stun_port)
            err = ret['Err']
            if not err: break
    if err: s.close(); return Blocked, None, None
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    exIP = ret['ExternalIP']
    exPort = ret['ExternalPort']
    stunIP = ret['ResponseIP']
    changedIP = ret['OtherIP']
    changedPort = ret['OtherPort']
    if ret['ExternalIP'] == source_ip: s.close(); return OpenInternet, exIP,exPort
    if not changedIP or not changedPort or changedIP==stunIP or changedPort==stun_port:
        log.debug('NAT discovery feature not supported by this server')
        s.close(); return TestingError, None, None
    exAddr1 = exIP+':'+str(exPort)

    # Test II: Send Binding Request to the other IP but primary port
    log.debug('# Test II: Send Binding Request to the other IP but primary port')
    ret = stun_test(s, changedIP, stun_port)
    if ret['Err']: s.close(); return TestingError, None, None
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    exAddr2 = ret['ExternalIP']+':'+str(ret['ExternalPort'])

    # Test III: Send Binding Request to the other IP and port
    log.debug('# Test III: Send Binding Request to the other IP and port')
    ret = stun_test(s, changedIP, changedPort)
    if ret['Err']: s.close(); return TestingError, None, None
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    exAddr3 = ret['ExternalIP']+':'+str(ret['ExternalPort'])

    # Assert mapping type
    s.close()
    if exAddr1 == exAddr2:
        if exAddr2 == exAddr3: return EndpointIndependent, exIP,exPort
        else: return PortDependent, exIP,exPort
    else:
        if exAddr2 != exAddr3: return AddressPortDependent, exIP,exPort
        else: return AddressDependent, exIP,exPort

# RFC5780: 4.4.+  Determining NAT Filtering Behavior (4 types)
def check_filtering_type(source_ip='0.0.0.0', source_port=0, stun_host=None, stun_port=3478):
    s = open_socket(source_ip, source_port)

    # Test I: Send regular Binding Request
    log.debug('# Test I: Send regular Binding Request')
    err = True
    if stun_host:
        ret = stun_test(s, stun_host, stun_port)
        err = ret['Err']
    else:
        for stun_host in stun_servers_list:
            log.debug('trying STUN host: %s', stun_host)
            ret = stun_test(s, stun_host, stun_port)
            err = ret['Err']
            if not err: break
    if err: s.close(); return Blocked, None, None
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    exIP = ret['ExternalIP']
    exPort = ret['ExternalPort']
    stunIP = ret['ResponseIP']

    # Test II: Request to change both IP and port
    s.close(); s = open_socket(source_ip, source_port)
    log.debug('# Test II: Request to change both IP and port')
    ret = stun_test(s, stunIP, stun_port, changeRequest(True,True), classic=True)
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    if not ret['Err']: s.close(); return EndpointIndependent, exIP,exPort
    elif ret['Err'] != 'Timeout': s.close(); return TestingError, exIP,exPort

    # Test III: Request to change port only
    s.close(); s = open_socket(source_ip, source_port)
    log.debug('# Test III: Request to change port only')
    ret = stun_test(s, stunIP, stun_port, changeRequest(chPort=True), classic=True)
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    if not ret['Err']: s.close(); return AddressDependent, exIP,exPort
    elif ret['Err'] != 'Timeout': return TestingError, exIP,exPort

    # Test IV: Request to change IP only
    s.close(); s = open_socket(source_ip, source_port)
    log.debug('# Test IV: Request to change IP only')
    ret = stun_test(s, stunIP, stun_port, changeRequest(chIP=True), classic=True)
    log.debug('result: %s', dumps(ret, indent=4, sort_keys=True))
    if not ret['Err']: s.close(); return PortDependent, exIP,exPort
    elif ret['Err'] != 'Timeout': return TestingError, exIP,exPort
    else: return AddressPortDependent, exIP,exPort


def make_argument_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-m', '--mapping', action='store_true',
        help='Discover the type of mapping between internal address and external address (RFC5780)'
    )
    parser.add_argument(
        '-f', '--filtering', action='store_true',
        help='Discover the type of inbound address filtering (RFC5780)'
    )
    parser.add_argument(
        '-d', '--debug', action='store_true',
        help='Enable debug logging'
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
        help='Network interface from which client sends Binding Request'
    )
    parser.add_argument(
        '-p', '--source-port', type=int,
        default=DEFAULTS['source_port'],
        help='Port to listen on for client'
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
            
        if not options.mapping and not options.filtering:
            fprint('{}'.format('- Discovering NAT type (it may take 5 to 60 seconds) ...'))
            nat_type, exIP,exPort = check_nat_type(
                options.source_ip, options.source_port,
                options.stun_host, options.stun_port
            )
            fprint('{}\n'.format('-' * 60))
            fprint('\tNAT Type: {}'.format(nat_type))
            fprint('\tExternal IP: {}'.format(exIP))
            fprint('\tExternal Port: {}'.format(exPort))
            fprint('\n{}'.format(('-' * 60)))

        if options.mapping:
            fprint('{}'.format('- Discovering NAT mapping type (it may take 5 to 10 seconds) ...'))
            mapping_type, exIP,exPort = check_mapping_type(
                options.source_ip, options.source_port,
                options.stun_host, options.stun_port
            )
            nat_type = 'Mapping: '+mapping_type
            fprint('{}\n'.format('-' * 60))
            fprint('\tNAT Mapping Type: {}'.format(mapping_type))
            fprint('\tExternal IP: {}'.format(exIP))
            fprint('\tExternal Port: {}'.format(exPort))
            fprint('\n{}'.format(('-' * 60)))

        if options.filtering:
            fprint('{}'.format('- Discovering NAT filtering type (it may take 5 to 10 seconds) ...'))
            filtering_type, exIP,exPort = check_filtering_type(
                options.source_ip, options.source_port,
                options.stun_host, options.stun_port
            )
            nat_type = '  Filtering: '+filtering_type
            fprint('{}\n'.format('-' * 60))
            fprint('\tNAT Filtering Type: {}'.format(filtering_type))
            fprint('\tExternal IP: {}'.format(exIP))
            fprint('\tExternal Port: {}'.format(exPort))
            fprint('\n{}'.format(('-' * 60)))


        if options.json:
            print dumps({
                'type': nat_type,
                'external_ip': exIP,
                'external_port': exPort
            }, indent=4)

    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
