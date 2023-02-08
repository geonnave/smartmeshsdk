import pprint
import json
from bottle import route, run, request
import paho.mqtt.client as mqtt
import requests
import re

TOPIC = "iotprona"
TOPIC_DOWNSTREAM = "iotprona/sendData"

#============================ receive from manager ============================

@route('<path:path>', method='ANY')
def all(path):
    global mqtt_client
    notif = json.loads(request.body.getvalue())
    msg = {}
    if notif['name']=='oap' and notif['fields']['channel_str']=='temperature':
        mac         = notif['mac']
        temperature = notif['fields']['samples'][0]/100.0
        msg['mac'] = mac
        msg['temperature'] = temperature
    elif notif['name']=='notifData':
        mac         = notif['fields']['macAddress']
        data        = notif['fields']['data']
        msg['mac']  = mac
        msg['data'] = data
    print(msg)
    mqtt_client.publish(TOPIC, payload=json.dumps(msg))
#============================ receive from broker =============================

def mqtt_on_message(client, userdata, msg):
    payload = msg.payload.decode('ascii')
    print('from MQTT: {}'.format(payload))

    mac = payload.split(' ')[0].lower()
    httppayload = payload.replace(mac, '')
    httppayload = httppayload.replace(' ', '', 1)

    mac = '00-17-0d-00-00-{}-{}-{}'.format(mac[0:2],mac[2:4],mac[4:6])


    requests.post(
            'http://127.0.0.1:8080/api/v2/raw/sendData'.format(mac),
            json={'payload': httppayload,
                  'manager': '/dev/tty.usbserial-142303',
                  'mac': mac },
            )
#============================ connect MQTT ====================================

def mqtt_on_connect(client, userdata, flags, rc):
    client.subscribe(TOPIC_DOWNSTREAM)
    print("MQTT connected")

mqtt_client = mqtt.Client()
mqtt_client.on_connect = mqtt_on_connect
mqtt_client.on_message = mqtt_on_message
mqtt_client.connect("broker.mqttdashboard.com", 1883, 60)
mqtt_client.loop_start()

#============================ sart web server =================================

run(host='localhost', port=1880, quiet=True)