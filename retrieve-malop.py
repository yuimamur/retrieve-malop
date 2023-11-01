import requests
import json
import subprocess
import time
import datetime

username = ""
password = ""
server = ""
port = ""

data = {
    "username": username,
    "password": password
}

def fetch_data(server, port, data, time_range_start, time_range_end):
    base_url = f"https://{server}:{port}"
    login_url = f"{base_url}/login.html"

    # データ取得
    endpoint_url = "/rest/mmng/v2/malops"
    api_url = base_url + endpoint_url

    query = json.dumps({
        "search": {},
        "range": {
            "from": time_range_start,
            "to": time_range_end
        },
        "pagination": {
            "pageSize": 50,
            "offset": 0
        },
        "federation": {
            "groups": []
        },
        "sort": [{
            "field": "LastUpdateTime",
            "order": "desc"
        }]
    })

    headers = {"Content-Type": "application/json"}
    api_response = session.request("POST", api_url, data=query, headers=headers)
    your_response = json.loads(api_response.content)
    malops = your_response['data']['data']

    return malops

# Unix Time ミリ秒
# time_range_start = 1685631312000;
# time_range_end = 1701278264000
time_range_start = int((time.time() - 5 * 24 * 3600) * 1000)
time_range_end = int(time.time() * 1000)

malops = fetch_data(server, port, data, time_range_start, time_range_end)


def convert_unix_milliseconds_to_datetime(epoch_milliseconds):
    epoch_seconds = epoch_milliseconds / 1000
    return datetime.datetime.utcfromtimestamp(epoch_seconds)

result_list = []
for malop in malops:
    malop_dict = {
        "detectionEngines": malop.get("detectionEngines", []),
        "detectionTypes": malop.get("detectionTypes", ""),
        "displayName": malop.get("displayName", ""),
        "rootCauseElementType": malop.get("rootCauseElementType", ""),
        "machine": malop.get("machines", ""),
        "user": malop.get("users", ""),
        "lastUpdateTime" : malop.get("lastUpdateTime",""),
        "severity" : malop.get("severity",""),
        "guid" : malop.get("guid",""),
    }
    result_list.append(malop_dict)


for item in result_list:

    result_detectionEngines = f"マルウェアは{ item['detectionEngines'][0] }で検知されました。"
    result_detectionTypes = f"根本原因は「{item['detectionTypes'][0]}」です。"
    result_rootCauseElementType = f"根本原因の要素は{ item['rootCauseElementType'] }です。"
    result_displayName = f"検知した悪意のあるプロセス・ファイルは{item['displayName']}です。"
    severity = f"アラートのシビリティは{item['severity']}です。"
    guid = f"Malop ID は{item['guid']}です。"
    data_machine = item['machine']
    display_names_machine = [item_temp['displayName'] for item_temp in data_machine]
    result_machine = f"対象の端末名は{display_names_machine[0]}です。"
    data_user = item['user']
    display_names_user = [item1_temp['displayName'] for item1_temp in data_user]
    epoch_milliseconds = item['lastUpdateTime']
    original_time = convert_unix_milliseconds_to_datetime(epoch_milliseconds)
    result_user = f"対象ユーザ名は{', '.join(display_names_user)}です。"
    formatted_timestamp = original_time.strftime("%Y年%m月%d日 %H時%M分%S秒")
    result_timestamp = f"発生時刻は{formatted_timestamp}です。"

    #combined_result = result_timestamp + "\n" + guid + "\n" + result_displayName + "\n" + result_detectionEngines +  "\n" + severity + "\n" + result_detectionTypes + "\n" + result_rootCauseElementType + "\n" + result_machine + "\n" + result_user
    # combined_result = [result_timestamp, guid, result_displayName, result_detectionEngines, severity,result_detectionTypes, result_rootCauseElementType, result_machine, result_user]

    combined_result = {
        "time": result_timestamp,
        "displayName": result_displayName,
        "detectionEngines": result_detectionEngines,
        "severity": severity,
        "detectionTypes": result_detectionTypes,
        "rootCauseElementType": result_rootCauseElementType,
        "result_machine": result_machine,
        "result_user": result_user
    }

    combined_result1 = f"{result_timestamp}\n"
    combined_result1 += f"{result_detectionTypes}\n"
    combined_result1 += f"{severity}\n"
    combined_result1 += f"{result_machine}\n"

    print(combined_result1)
    print("\n")


#    cmd = f'zabbix_sender -z 127.0.0.1 -s "Zabbix server" -k "key" -o {combined_result1}'
#    print(cmd)
#    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
#    output, error = process.communicate()
#    print(output)

    time.sleep(1)
