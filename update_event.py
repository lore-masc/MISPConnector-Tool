from pymisp import PyMISP
from os.path import isfile, join
import json
import sys

def init(url, key):
    return PyMISP(url, key, False, 'json', debug=False)

CONFIG_FILE = "config.txt"
lines = [line.rstrip('\n') for line in open(CONFIG_FILE)]
misp_url = lines[0]
misp_key = lines[1]

misp = init(misp_url, misp_key)

if len(sys.argv) == 2:
        json_data = open(sys.argv[1]).read()
        event_to_import = json.loads(json_data)
else:
        print("Error: You moust specify the json file to import")
        sys.exit(0)

event_info =  event_to_import['info']
event_threat = event_to_import['threat']
event_distrib = event_to_import['distribution']
event_sg = event_to_import['sharing_group']
event_analysis = event_to_import['analysis']
event_date = event_to_import['data']
event_comment = event_to_import['comment']
event_tlp = "tlp:" + event_to_import['tlp']
event_platform = event_to_import['platform']
event_iocs = event_to_import['iocs']

if len(event_sg) != 0:
        event = misp.new_event(4, event_threat, event_analysis, event_info, event_date, sharing_group_id=event_sg)
else:
        event = misp.new_event(event_distrib, event_threat, event_analysis, event_info, event_date)

misp.add_named_attribute(event, 'comment', event_comment)
for ioc in event_iocs:
        res = misp.freetext(event['Event']['id'], ioc['value'])

        #Il freetext non riconosce la categoria dell'attributo
        #if len(res['response']) == 0 and ioc['value'].find('|') != -1:
        if len(res['response']) == 0:
                misp.add_named_attribute(event, 'other', ioc['value'], to_ids=True)
        #Il freetext aggiunge un ip-dst, duplica
        if len(res['response']) != 0 and res['response'][0]['type'] == "ip-dst":
                misp.add_named_attribute(event, 'ip-src', ioc['value'], to_ids=True)
for platform in event_platform:
        misp.tag(event['Event']['uuid'], "ms-caro-malware:malware-platform=" + platform['name'])
misp.tag(event['Event']['uuid'], event_tlp)
misp.fast_publish(event['Event']['id'])
print(event_info + " added: " + event['Event']['uuid'] + "\n")
sys.exit(0)