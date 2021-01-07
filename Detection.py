import requests
import json
import time
from aip import AipContentCensor
import hashlib
import os
from dbcon import PGConnect

pg = PGConnect(host="10.21.13.154", port=5432, user="checker", password="lsl213", database="inno")


def get_md5_01(file_path):
    md5 = None
    if os.path.isfile(file_path):
        f = open(file_path, 'rb')
        md5_obj = hashlib.md5()
        md5_obj.update(f.read())
        hash_code = md5_obj.hexdigest()
        f.close()
        md5 = str(hash_code).lower()
    return md5


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass

    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass

    return False


class Detect:
    cnt = 0
    pictureAverageTime = 0
    textAverageTime = 0

    def __init__(self):
        self.pictureAverageTime = 0
        self.textAverageTime = 0
        self.cnt = 0

    def detectText(self, file_name):
        print("Detect Text: {}".format(file_name))
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': '83565b51aded4f0c66da0555df3089636c62a3cc7be8f01ad71df836ebfbded5'}
        files = {'file': (file_name, open(file_name, 'rb'))}
        md5 = get_md5_01(file_name)
        while True:
            try:
                before = time.time()
                pg.sel_statement(md5)
                res = pg.get_result_set()
                output1 = None
                if res is not None:
                    output1 = res
                else:
                    response = requests.post(url, files=files, params=params)
                    output1 = response.json()
                    pg.insert_statement(output1)
                after = time.time()
                print(after - before)
                self.cnt += 1
                self.textAverageTime += after - before
                break
            except Warning:
                print("Queuing...")

        md5 = output1['md5']
        scan_id = output1['scan_id']
        # get the report
        url = 'https://www.virustotal.com/vtapi/v2/file/report'

        params = {'apikey': '83565b51aded4f0c66da0555df3089636c62a3cc7be8f01ad71df836ebfbded5', 'resource': md5,
                  'scan_id': scan_id, 'allinfo': True}
        result = {}
        # result = {"scans": {}, 'total': output2['total'], 'positives': output2['positives'], 'md5': output2['md5']}
        while True:
            try:
                pg.sel_statement(md5)
                res = pg.get_result_set()
                if res is not None:
                    output2 = res
                else:
                    response = requests.get(url, params=params)
                    output2 = response.json()
                print(output2)
                if output2['positives'] > 0:
                    result = {"scans": {}, 'total': output2['total'], 'positives': output2['positives'],
                              'md5': output2['md5'],
                              "conclusion": "不合规"}
                else:
                    result = {"scans": {}, 'total': output2['total'], 'positives': output2['positives'],
                              'md5': output2['md5'],
                              "conclusion": "合规"}
                break
            except Warning:
                print("Queuing...")
        for corp in output2["scans"].items():
            for items in corp[1].items():
                if items[0] == 'detected' and items[1] is not False:
                    result['scans'][corp[0]] = corp[1]
        isExists = os.path.exists('./FileResult')
        if not isExists:
            os.makedirs('./FileResult')
        os.chdir('./FileResult')
        json_str = json.dumps(result, indent=4)
        with open(('{}_detection_result.json'.format(file_name.split('.')[0])), 'w') as json_file:
            json_file.write(json_str)
        os.chdir('..')

    def detectPicture(self, file_name):
        print("Detect Picture")

        APP_ID = '23065324'
        API_KEY = 'ZiDIBN37iBIrUm06Llxrpvcj'
        SECRET_KEY = 'Kw6sQs80MDrBFOrqICghUGG2SIvqywUv'

        md5 = get_md5_01(file_name)
        pg.sel_statement(md5)
        res = pg.get_result_set()

        before = time.time()
        if res is not None:
            result = res
        else:
            client = AipContentCensor(APP_ID, API_KEY, SECRET_KEY)
            result = client.imageCensorUserDefined(get_file_content(file_name))
        after = time.time()
        print(after - before)
        # self.cnt += 1
        # self.pictureAverageTime += after-before
        print(result)

        isExists = os.path.exists('./PictureResult')
        if not isExists:
            os.makedirs('./PictureResult')
        os.chdir('./PictureResult')
        with open('{}_detection_result.json'.format(file_name.split('.')[0]), 'w') as json_file:
            json_file.write('{\n')
            json_file.write('"log_id": "{}",\n'.format(result['log_id']))
            json_file.write('"md5": "{}",'.format(md5))
            if result['conclusion'] == '合规':
                json_file.write('\n')
                json_file.write('"conclusion" : "合规"}')
            else:
                json_file.write('\n')
                json_file.write('"conclusion": "{}"\n'.format(result['data'][0]['msg']))
                json_file.write('}')
        os.chdir('..')


def get_file_content(filePath):
    with open(filePath, 'rb') as fp:
        return fp.read()


detect = Detect
for fileName1 in os.listdir('.'):
    if is_number(fileName1[0]):
        os.chdir(fileName1)
        for fileName2 in os.listdir('.'):
            if fileName2 == 'text':
                os.chdir(fileName2)
                for fileName3 in os.listdir('.'):
                    if fileName3 == 'html':
                        os.chdir(fileName3)
                        for items in os.listdir('.'):
                            if items.endswith('.html'):
                                detect.detectText(self=detect, file_name=items)
                                time.sleep(30)
                                # print(items)
                        os.chdir('..')
os.chdir("..")
os.chdir("..")
print("Text Average Detection Time: {}".format(detect.textAverageTime / detect.cnt))
detect.cnt = 0
for fileName1 in os.listdir('.'):
    if is_number(fileName1[0]):
        os.chdir(fileName1)
        for fileName2 in os.listdir('.'):
            if fileName2 == 'image':
                os.chdir(fileName2)
                for fileName3 in os.listdir('.'):
                    os.chdir(fileName3)
                    for items in os.listdir('.'):
                        if items.endswith('.{}'.format(fileName3)):
                            detect.detectPicture(detect, items)
                    os.chdir('..')

print("Picture Average Detection Time: {}".format(detect.pictureAverageTime / detect.cnt))
