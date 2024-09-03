from bottle import route, run, request
from dataclasses import dataclass
from lakers import EdhocResponder, AuthzAutenticator
from random import randint
from typing import Optional
import paho.mqtt.client as mqtt
import json
import lakers
import requests
import sys
import logging

if len(sys.argv) == 2:
    MANAGER_SERIAL = sys.argv[1]
else:
    MANAGER_SERIAL = '/dev/tty.usbserial-144303'

logging.basicConfig(level=logging.DEBUG)

TOPIC = "aiotacademy"

R = bytes.fromhex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac")
CRED_I = bytes.fromhex("A2027734322D35302D33312D46462D45462D33372D33322D333908A101A5010202412B2001215820AC75E9ECE3E50BFC8ED60399889522405C47BF16DF96660A41298CB4307F7EB62258206E5DE611388A4B8A8211334AC7D37ECB52A387D257E6DB3C2A93DF21FF3AFFC8")
CRED_R = bytes.fromhex("A2026008A101A5010202410A2001215820BBC34960526EA4D32E940CAD2A234148DDC21791A12AFBCBAC93622046DD44F02258204519E257236B2A0CE2023F0931F1F386CA7AFDA64FCDE0108C224C51EABF6072")


@dataclass
class OngoingEdhocSession:
    responder: EdhocResponder
    authz_authenticator: Optional[AuthzAutenticator] = None
    loc_w: Optional[str] = None


# dictionary that holds the different responders multiplexed according to the connection identifier C_R
ongoing_sessions = {}
authorized_motes = {}

#============================ receive from manager ============================

@route('<path:path>', method='ANY')
def all(path):
    global mqtt_client
    message = json.loads(request.body.getvalue())

    if message['name']=='notifData':
        mac = message['fields']['macAddress']
        data = message['fields']['data']
        if is_edhoc_message_1(data):
            handle_edhoc_message_1(mac, data)
        elif is_edhoc_message_3(data):
            handle_edhoc_message_3(mac, data)
        elif is_eap_edhoc_message(data):
            handle_eap_edhoc(mac, data)
        else: # check if mote is authorized, if so publish on MQTT
            if mac in authorized_motes.keys():
                try:
                    print("Mote {} published: {}".format(mac, ''.join(chr(x) for x in data)))
                except:
                    print("Mote {} published: {}".format(mac, data))
                mqtt_client.publish(TOPIC, payload=json.dumps(data))
            else:
                print("Unauthorized message from {}".format(mac))
    else:
        # periodic health reports sent by the device, ignore
        pass

def request_voucher(
    responder: lakers.EdhocResponder,
    ead_1: bytes,
    message_1: bytes,
    c_r: bytes,
):
    authz_authenticator = lakers.AuthzAutenticator()
    loc_w, voucher_request = authz_authenticator.process_ead_1(ead_1, message_1)
    voucher_request_url = f"{loc_w}/.well-known/lake-authz/voucher-request"
    logging.info(f"Requesting voucher at {voucher_request_url} with voucher request {voucher_request.hex(' ').upper()}")
    response = requests.post(voucher_request_url, data=voucher_request)
    if response.status_code == 200:
        logging.info(f"Got an ok voucher response: {response.content.hex(' ').upper()}")
        ead_2 = authz_authenticator.prepare_ead_2(response.content)
        print(f">> ead_2: {ead_2.value().hex(' ').upper()}")
        message_2 = responder.prepare_message_2(
            lakers.CredentialTransfer.ByValue, c_r, ead_2
            # lakers.CredentialTransfer.ByReference, c_r, ead_2
        )
        ongoing_sessions[c_r] = OngoingEdhocSession(
            responder, authz_authenticator, loc_w
        )
        return message_2
    else:
        raise Exception(f"Error requesting voucher {response.status_code}")

def fragment_message(message, max_fragment_size=80):
    print(f"Fragmenting message of {len(message)} bytes")
    fragments = []
    num_fragments = (len(message) + max_fragment_size - 1) // max_fragment_size

    if num_fragments == 1:
        print(f"Single fragment")
        return [b'\x00' + message]
    else:
        print(f"Total of {num_fragments} fragments")
        for i in range(num_fragments):
            start = i * max_fragment_size
            end = start + max_fragment_size
            
            fragment = message[start:end]
            
            # Adding a header: first byte is a flag for the fragment type
            if i == 0:
                # Start of the message
                header = b'\x01'
            elif i == num_fragments - 1:
                # End of the message
                header = b'\x03'
            else:
                # Middle fragment
                header = b'\x02'
            
            fragments.append(header + fragment)
    
    return fragments

def handle_edhoc_message_1(mac, message_1):
    try:
        message_1 = message_1[1:]
        print(f"Message 1 ({len(message_1)} bytes) from {mac} received")
        # create new responder
        responder = lakers.EdhocResponder(R, CRED_R)
        c_r = bytes([randint(0, 24)])
        _c_i, ead_1 = responder.process_message_1(message_1)

        if ead_1 and ead_1.label() == lakers.consts.EAD_AUTHZ_LABEL:
            message_2 = request_voucher(responder, ead_1, message_1, c_r)
        else:
            # message_2 = responder.prepare_message_2(lakers.CredentialTransfer.ByValue, c_r, None)
            message_2 = responder.prepare_message_2(lakers.CredentialTransfer.ByReference, c_r, None)
            # save the responder into existing sessions
            ongoing_sessions[c_r] = OngoingEdhocSession(responder)

        print(f"Sending message 2 ({len(message_2)}) bytes to {mac}")
        for fragment in fragment_message(message_2):
            print(f"Sending fragment ({len(fragment)} bytes): {fragment.hex(' ').upper()}")
            requests.post(
                'http://127.0.0.1:8080/api/v2/raw/sendData',
                json={'payload': list(fragment),
                'manager': MANAGER_SERIAL,
                'mac': mac },
            )
    except Exception as e:
        print("Exception in message_1 handling from {}. Exception: {}".format(mac, e))

def handle_edhoc_message_3(mac, message_3):
    # EDHOC message 3, retrieve the responder
    try:
        print(f"Message 3 ({len(message_3)}) from {mac} received")
        c_r = bytes([message_3[0]])
        responder = ongoing_sessions[c_r].responder

        id_cred_i, ead_3 = responder.parse_message_3(message_3[1:])
        valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_I)
        r_prk_out = responder.verify_message_3(valid_cred_i)
        print("Handshake with {} completed. PRK_OUT: {}".format(mac, ' '.join(hex(x) for x in r_prk_out)))
        ongoing_sessions.pop(c_r)
        authorized_motes[mac] = r_prk_out
    except Exception as e:
        print("Exception in message_3 handling from {}. Exception {}".format(mac, e))

# Check whether a message is an EDHOC messsage based on first byte
def is_edhoc_message(data):
    if is_edhoc_message_1(data) or is_edhoc_message_3(data):
        return True
    else:
        return False

def is_edhoc_message_1(data):
    if data[0] == 0xf5:
        return True

def is_edhoc_message_3(data):
    if bytes([data[0]]) in ongoing_sessions.keys():
        return True

def post_data_to_mote(mac, data):
    print(f"Sending EAP-EDHOC message to {mac} ({len(data)} bytes): {data.hex().upper()}")
    requests.post(
        'http://127.0.0.1:8080/api/v2/raw/sendData',
        json={'payload': list(data),
        'manager': MANAGER_SERIAL,
        'mac': mac },
    )

from eap_edhoc import EAPBuilder, EAP, EAP_EDHOC
import eap_edhoc

# EAP-Request/Identity: 5 bytes
eap_packet_1 = EAPBuilder.decode(bytes.fromhex('0101000501'))
# EAP-Response/Identity: 16 bytes
eap_packet_2 = EAPBuilder.decode(bytes.fromhex('02010010016578616D706C652E636F6D'))
# EAP-Request/EAP-EDHOC Start: 6 bytes
eap_packet_3 = EAPBuilder.decode(bytes.fromhex('010100067F10'))
# EAP-Response/EAP-EDHOC message_1: 45 bytes
eap_packet_4 = EAPBuilder.decode(bytes.fromhex('0201002C7F0126F50302582053624A2DD3535812439AA2A0C2793342CD0BD81B2872D70D370911FDEA48A81C29'))
# EAP-Request/EAP-EDHOC message_2: 137 bytes
eap_packet_5 = EAPBuilder.decode(bytes.fromhex('010100887F01825880EF929ED9786CF0F9272E7BD4604F074903CFA251970C991BB0C769F4DEB83A94E6E008DF6D02147A83C5643B1363327615A8DE483EFE76FAD034BB8C215E92AB5EBBF5C2AEF64939FAB1EC4484AA380DA454138681A41EF54832D2A36BA945055DE6BBB81835CB6DC0629BC578105D99E68503B96AA64C8D5FA18262BE1DD55B'))
# EAP-Response/EAP-EDHOC message_3: 27 bytes
eap_packet_6 = EAPBuilder.decode(bytes.fromhex('0201001A7F011401521B481E940F98787D722A8743068EAA8B2965'))
# EAP-Request/EAP-EDHOC message_4: 23 bytes
eap_packet_7 = EAPBuilder.decode(bytes.fromhex('010100167F011066656665666566656665666566656665'))
# EAP-Response/EAP-EDHOC: 6 bytes
eap_packet_8 = EAPBuilder.decode(bytes.fromhex('020100067F00'))
# EAP-Success: 4 bytes
eap_packet_9 = EAPBuilder.decode(bytes.fromhex('03010004'))


def handle_eap_edhoc_message_1(mac, message_1):
    try:
        message_1 = message_1[1:]
        print(f"EAP Message 1 ({len(message_1)} bytes) from {mac} received: {message_1.hex().upper()}")
        # create new responder
        responder = lakers.EdhocResponder(R, CRED_R)
        c_r = bytes([randint(0, 24)])
        _c_i, ead_1 = responder.process_message_1(message_1)

        # message_2 = responder.prepare_message_2(lakers.CredentialTransfer.ByValue, c_r, None)
        message_2 = responder.prepare_message_2(lakers.CredentialTransfer.ByValue, c_r, None)
        # save the responder into existing sessions
        ongoing_sessions[c_r] = OngoingEdhocSession(responder)

        # prepare packet 5 (EAP-Request/EAP-EDHOC message_2)
        eap_edhoc_message_2 = EAPBuilder.eap_edhoc_request(message_2).encode()

        return fragment_message(eap_edhoc_message_2)
    except Exception as e:
        print("Exception in message_1 handling from {}. Exception: {}".format(mac, e))

def handle_eap_edhoc_message_3(mac, message_3):
    # EDHOC message 3, retrieve the responder
    try:
        print(f"EAP Message 3 ({len(message_3)}) from {mac} received")
        c_r = bytes([message_3[0]])
        responder = ongoing_sessions[c_r].responder

        id_cred_i, ead_3 = responder.parse_message_3(message_3[1:])
        valid_cred_i = lakers.credential_check_or_fetch(id_cred_i, CRED_I)
        r_prk_out = responder.verify_message_3(valid_cred_i)
        print("Handshake with {} completed. PRK_OUT: {}".format(mac, ' '.join(hex(x) for x in r_prk_out)))
        ongoing_sessions.pop(c_r)
        authorized_motes[mac] = r_prk_out

        return fragment_message(eap_packet_7.encode())
    except Exception as e:
        print("Exception in message_3 handling from {}. Exception {}".format(mac, e))

def handle_eap_edhoc(mac, data):
    data = bytes(data)
    print(f"EAP-EDHOC message ({len(data)} bytes) from {mac} received: {data.hex().upper()}")
    pac = EAPBuilder.decode(data)

    if pac.match_header(eap_packet_2):
        print(f"This is packet 2, sending packet 3")
        post_data_to_mote(mac, b'\x00' + eap_packet_3.encode())
    elif pac.match_header(eap_packet_4) and pac.has_data() and is_edhoc_message_1(pac.data):
        print(f"This is packet 4, sending packet 5")
        message_2_fragments = handle_eap_edhoc_message_1(mac, pac.data)
        print(f"Sending EAP-EDHOC message_2: {[f.hex(' ').upper() for f in message_2_fragments]}")
        for fragment in message_2_fragments:
            post_data_to_mote(mac, fragment)
    elif pac.match_header(eap_packet_6) and pac.has_data() and is_edhoc_message_3(pac.data):
        print(f"This is packet 6, sending packet 7")
        message_3_fragments = handle_eap_edhoc_message_3(mac, pac.data)
        print(f"Sending EAP-EDHOC message_4: {[f.hex(' ').upper() for f in message_3_fragments]}")
        for fragment in message_3_fragments:
            post_data_to_mote(mac, fragment)
    elif pac.match_header(eap_packet_8):
        print(f"This is packet 8, sending packet 9")
        post_data_to_mote(mac, b'\x00' + eap_packet_9.encode())

def is_eap_edhoc_message(data):
    try:
        print(f"Trying to decode EAP message: {bytes(data).hex().upper()}")
        EAPBuilder.decode(bytes(data))
        return True
    except Exception as e:
        print(f"Exception: {e}")
        return False

#============================ connect MQTT ====================================
def mqtt_on_message(client, userdata, msg):
    pass

def mqtt_on_connect(client, userdata, flags, rc):
    print("MQTT connected")

mqtt_client = mqtt.Client()
mqtt_client.on_connect = mqtt_on_connect
mqtt_client.on_message = mqtt_on_message
mqtt_client.connect("broker.mqttdashboard.com", 1883, 60)
mqtt_client.loop_start()

#============================ start web server =================================

run(host='localhost', port=1880, quiet=True)
