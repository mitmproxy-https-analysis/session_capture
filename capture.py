from base64 import encodestring
from threading import Lock, Thread
from queue import Queue
import base64
import json
import os

from mitmproxy import ctx

FILE_WORKERS = 1
HTTP_WORKERS = 10
# for use of transfer strings to bytes
DICTION = {'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13,
           't': 9, 'v': 11, "'": 39, '"': 34, '?': 63, '0': 0}
# for use of different ip id
ID_POOL = {}

# set the root directory of the project
HOME = "C:\\projects\\mitmproxy_group_I"


class JSONDumper:

    def __init__(self):
        self.outfile = None
        self.transformations = None
        self.encode = None
        self.url = None
        self.lock = None
        self.auth = None
        self.queue = Queue()

    def done(self):  # 结束时候调用
        self.queue.join()
        if self.outfile:
            self.outfile.close()

    fields = {
        'timestamp': (
            ('error', 'timestamp'),

            ('request', 'timestamp_start'),
            ('request', 'timestamp_end'),

            ('response', 'timestamp_start'),
            ('response', 'timestamp_end'),

            ('client_conn', 'timestamp_start'),
            ('client_conn', 'timestamp_end'),
            ('client_conn', 'timestamp_tls_setup'),

            ('server_conn', 'timestamp_start'),
            ('server_conn', 'timestamp_end'),
            ('server_conn', 'timestamp_tls_setup'),
            ('server_conn', 'timestamp_tcp_setup'),
        ),
        'ip': (
            ('server_conn', 'source_address'),
            ('server_conn', 'ip_address'),
            ('server_conn', 'address'),
            ('client_conn', 'address'),
        ),
        'ws_messages': (
            ('messages',),
        ),
        'headers': (
            ('request', 'headers'),
            ('response', 'headers'),
        ),
        'content': (
            ('request', 'content'),
            ('response', 'content'),
        ),
    }  # 列表，每一个元素是一个dict

    def _init_transformations(self):  # 自己设置用来改变transformations这个数组
        self.transformations = [
            {
                'fields': self.fields['headers'],
                'func': dict,
            },
            {
                'fields': self.fields['timestamp'],
                'func': lambda t: int(t * 1000),
            },
            {
                'fields': self.fields['ip'],
                'func': lambda addr: {
                    'host': addr[0].replace('::ffff:', ''),
                    'port': addr[1],
                },  # 把address分成两份
            },
            {
                'fields': self.fields['ws_messages'],
                'func': lambda ms: [{
                    'type': m[0],
                    'from_client': m[1],
                    'content': base64.b64encode(bytes(m[2], 'utf-8')) if self.encode else m[2],
                    'timestamp': int(m[3] * 1000),
                } for m in ms],
            }
        ]

        if self.encode:
            self.transformations.append({
                'fields': self.fields['content'],
                'func': base64.b64encode,
            })  # 修正正文编码

    @staticmethod
    def transform_field(obj: dict, path: list, func):
        # 传入的obj是frame，也就是每一个response抓到的全部内容，提醒一下，frame是dict类型；传入的path是诸如 ('error', 'timestamp')这样的列表
        """
        Apply a transformation function `func` to a value
        under the specified `path` in the `obj` DICTIONary.
        """
        for key in path[:-1]:  # 这里取出来的path[]是一个列表，但只有一个元素，就是第一个元素,经过调试检查，这个key就是如'error'这样的字符串
            if not (key in obj and obj[key]):  # 表明存在这个dict对应关系
                return
            obj = obj[key]  # 这个就是取dict的对应结果，使得obj进入内层嵌套，也就是进入fields的第一层
        if path[-1] in obj and obj[path[-1]]:
            # path[-1]是最后一个数，如'source_address'，当存在时，就会调用函数，把这个值换成函数后的值，事实上，是用这个方式来实现正文的变换的
            obj[path[-1]] = func(obj[path[-1]])
            # 举一个例子，path[-1]中包括'address'这个key，当遍历到这里，就会查找有没有'address',如果有，调用115行的方法，把
            # "address": ["::ffff:10.21.114.253",37664,0,0]变成了{"host": "10.21.114.253","port": 49148}

    """可以直接调用@classmethod方法，不需要实例化"""
    @classmethod
    def convert_to_strings(cls, obj):
        """
        递归将dict中所有元素转换成strings
        Recursively convert all list/dict elements of type `bytes` into strings.
        """
        if isinstance(obj, dict):  # 如果传进的参数是DICTIONary
            return {cls.convert_to_strings(key): cls.convert_to_strings(value)
                    for key, value in obj.items()}
        elif isinstance(obj, list) or isinstance(obj, tuple):  # 如果传进的参数是list或者是tuple
            return [cls.convert_to_strings(element) for element in obj]
        elif isinstance(obj, bytes):  # 如果传进的参数是bytes
            return str(obj)[2:-1]
        return obj

    def worker(self):  # 这是每一步的写入框架
        while True:
            frame = self.queue.get()
            self.dump(frame)
            self.queue.task_done()

    def dump(self, frame):  # 具体写入的过程,这部分比较复杂
        global ID_POOL
        """
        Transform and dump (write / send) a data frame.
        """
        for tfm in self.transformations:  # 取出每一个对照函数，每一个tfm是一个dict
            # 再从中取出每一个dict里fileds所对应的值，可以从上面看到，这个值是fields函数里对应的列表，而从中进行for循环，取出来的field是一个更小的列表
            for field in tfm['fields']:
                # 这里就是简单的修改frame的对应了
                self.transform_field(frame, field, tfm['func'])
        # 值得一提的是，这个改变编码并不是用来改变content的内容的，而是去改变成json文件需要的编码格式，下面写入时候会用到
        frame = self.convert_to_strings(frame)  # 这里的frame都是string

        ip_address = frame['client_conn']["address"]['host']
        request_frame = frame['request']
        response_frame = frame['response']

        request_content = request_frame['content']
        request_content_obj = {'content': request_content}
        response_content = response_frame['content']
        response_content_obj = {'content': response_content}

        # set flag to see wheter to write request content or not
        rtc_flag = (len(request_content.strip()) != 0)
        # set flag to see whether to write response content or not
        rec_flag = (len(response_content.strip()) != 0)
        """clear the content"""
        request_frame['content'] = ""
        response_frame['content'] = ""

        first_subfile = 'others'
        second_subfile = 'others'
        if response_frame['headers'].__contains__('Content-Type') or response_frame['headers'].__contains__('content-type'):
            if response_frame['headers'].__contains__('Content-Type'):
                name = 'Content-Type'
            else:
                name = 'content-type'
            classification = response_frame['headers'][name].split('/')
            first_subfile = classification[0].replace(' ', '')
            second_subfile = classification[1].split(';')[0]
        self.lock.acquire()
        if not os.path.exists(ip_address):
            ID_POOL[ip_address] = 1
            os.makedirs(ip_address)
        os.chdir(ip_address)

        """进入分类文件夹"""
        if not os.path.exists(first_subfile):  # 进入一级文件夹
            os.makedirs(first_subfile)
        os.chdir(first_subfile)
        if len(second_subfile) != 0 and not os.path.exists(second_subfile):
            os.makedirs(second_subfile)
        if first_subfile != "others":
            os.chdir(second_subfile)
        session_id = ID_POOL[ip_address]
        request_filename = str(session_id)+'_request.json'

        """to write out the request information"""
        self.outfile = open(request_filename, 'a')
        self.outfile.write("\n" + json.dumps(request_frame) + "\n")

        """To write out the response information"""
        response_filename = str(session_id)+'_response.json'
        self.outfile = open(response_filename, 'a')
        self.outfile.write("\n" + json.dumps(response_frame) + "\n")

        """To write out the request content if any"""
        if rtc_flag:
            rtc_filename = str(session_id)+'_request_content.json'
            self.outfile = open(rtc_filename, 'a')
            self.outfile.write("\n"+json.dumps(request_content_obj)+'\n')

        """To write out the response content into right format file"""
        if rec_flag:
            # TODO: transfer string to bytes
            rec_filename = str(session_id)+'_response_content'
            self.string2bytes_format(
                second_subfile, rec_filename, response_content)
            rec_file = str(session_id)+'_response_content.json'
            self.outfile = open(rec_file, 'a')
            self.outfile.write('\n'+json.dumps(response_content_obj)+'\n')
        os.chdir(HOME)
        ID_POOL[ip_address] += 1
        self.lock.release()

    """transfer string to bytes, and store it in the right file"""
    @classmethod
    def string2bytes_format(cls, secondsubfile, filename, string):
        if secondsubfile == 'others':
            return
        i = 0
        with open(filename+'.'+secondsubfile, 'wb+') as fstb:
            while i < len(string):
                if string[i] == "\\":
                    if string[i+1] == 'x':
                        number = int(string[i+2:i+4], 16)
                        fstb.write(number.to_bytes(1, 'little'))
                        i += 4
                    elif DICTION.__contains__(string[i+1]):
                        number = DICTION[string[i+1]]
                        fstb.write(number.to_bytes(1, 'little'))
                        i += 2
                    else:
                        fstb.write(bytes(string[i], 'utf-8'))
                        i += 2
                else:
                    fstb.write(bytes(string[i], 'utf-8'))
                    i += 1

    @staticmethod
    def load(loader):  # 开始的时候load这些设置，会把这些东西加入到options里面，在下面的方法里面调用
        """
        Extra options to be specified in `~/.mitmproxy/config.yaml`.
        """
        loader.add_option('dump_encodecontent', bool, False,
                          'Encode content as base64.')
        loader.add_option('dump_destination', str, 'jsondump.out',
                          'Output destination: path to a file or URL.')
        loader.add_option('dump_username', str, '',
                          'Basic auth username for URL destinations.')
        loader.add_option('dump_password', str, '',
                          'Basic auth password for URL destinations.')

    def configure(self, _):
        """
        主体方法在这里，每次配置发生变化以后就会执行这个方法
        总的思路是，每次response都会把来回写进队列里面，然后触发发生，这个方法就启动了
        """
        """
        Determine the destination type and path, initialize the output
        transformation rules.
        """
        self.encode = ctx.options.dump_encodecontent  # 设置编码格式，其实不需要
        self.lock = Lock()
        ctx.log.info('Writing all data frames to %s' %
                     ctx.options.dump_destination)
        self._init_transformations()
        t = Thread(target=self.worker)
        t.daemon = True
        t.start()

    def response(self, flow):
        """
        Dump request/response pairs.
        """
        self.queue.put(flow.get_state())


addons = [JSONDumper()]  # pylint: disable=invalid-name
