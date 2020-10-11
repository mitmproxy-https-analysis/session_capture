from base64 import encodestring
from threading import Lock, Thread
from queue import Queue
import base64
import json
import os
"""
    # TODO: REMEMBER TO SHUT DOWN YOUR FIREWALLS!!!!!!!!!
    """
from mitmproxy import ctx
import constant


class JSONDumper:

    def __init__(self):
        self.outfile = None
        self.transformations = None
        self.encode = None
        self.url = None
        self.lock = None
        self.auth = None
        self.queue = Queue()

    def done(self):
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
    }

    def _init_transformations(self):
        """
            For fields data processing
        """
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
                },
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
            })

    @staticmethod
    def transform_field(obj, path, func):
        """
            :param obj: frame
            :param path: tuple, e.g. ('error', 'timestamp')
            :param func: function to operate
            Apply a transformation function `func` to a value under the specified `path` in the `obj` DICTIONary.
        """
        for key in path[:-1]:  # here to access the first element of path[], such as 'error'
            if not (key in obj and obj[key]):
                return
            obj = obj[key]  # to step into the first level of fields
        if path[-1] in obj and obj[path[-1]]:
            # path[-1] (e.g. 'source_address'), if exists, call the function and do the transformations
            obj[path[-1]] = func(obj[path[-1]])

    @classmethod
    def convert_to_strings(cls, obj):
        """
            :param obj: dict/list/bytes 
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

    def worker(self):
        """
            framework to write
        """
        while True:
            frame = self.queue.get()
            self.dump(frame)
            self.queue.task_done()

    def dump(self, frame):
        """
            :param frame: frame
            Transform and dump (write / send) a data frame.
        """
        for tfm in self.transformations:
            for field in tfm['fields']:
                self.transform_field(frame, field, tfm['func'])
        frame = self.convert_to_strings(frame)
        # to get the ip address of the client
        ip_address = frame['client_conn']["address"]['host']
        # to get the request & response
        request_frame = frame['request']
        response_frame = frame['response']
        # to get content of request & response respectively
        request_content = request_frame['content']
        request_content_obj = {'content': request_content}
        response_content = response_frame['content']
        response_content_obj = {'content': response_content}

        # set flag to see whether to write request content or not
        rtc_flag = (len(request_content.strip()) != 0)
        # set flag to see whether to write response content or not
        rec_flag = (len(response_content.strip()) != 0)

        # clear the content, since it can be very large, so we store it in another single file
        request_frame['content'] = ""
        response_frame['content'] = ""

        # set the first directory and second directory and file suffix
        first_subfile = 'others'
        second_subfile = 'others'
        file_suffix = ''

        # classification according to each frame's response headers' content-type
        if response_frame['headers'].__contains__('Content-Type') or response_frame['headers'].__contains__('content-type'):
            if response_frame['headers'].__contains__('Content-Type'):
                name = 'Content-Type'
            else:
                name = 'content-type'
            type_name = response_frame['headers'][name].split(';')[
                0].replace(' ', '')
            first_subfile = type_name.split('/')[0].replace(' ', '')
            second_subfile = type_name.split('/')[1].replace(' ', '')
            if constant.SUFFIX.__contains__(type_name):
                file_suffix = constant.SUFFIX[type_name][0]

            # classification = response_frame['headers'][name].split('/')
            # first_subfile = classification[0].replace(' ', '')
            # second_subfile = classification[1].split(';')[0]
        self.lock.acquire()
        if not os.path.exists(ip_address):
            # if ip appears first, set id to 1
            constant.ID_POOL[ip_address] = 1
            os.makedirs(ip_address)
        os.chdir(ip_address)

        # to step into file
        if first_subfile == 'others':
            if not os.path.exists(first_subfile):
                os.makedirs(first_subfile)
            os.chdir(first_subfile)
        else:
            if not os.path.exists(first_subfile):
                os.makedirs(first_subfile)
            os.chdir(first_subfile)
            if not os.path.exists(second_subfile):
                os.makedirs(second_subfile)
            os.chdir(second_subfile)
        # assign the id for each ip address
        session_id = constant.ID_POOL[ip_address]
        request_filename = str(session_id)+'_request.json'

        """
            to write out the request information
        """
        self.outfile = open(request_filename, 'a')
        self.outfile.write("\n" + json.dumps(request_frame) + "\n")

        """
            To write out the response information
        """
        response_filename = str(session_id)+'_response.json'
        self.outfile = open(response_filename, 'a')
        self.outfile.write("\n" + json.dumps(response_frame) + "\n")

        """
            To write out the request content if any
        """
        # if rtc_flag:
        #     rtc_filename = str(session_id)+'_request_content.json'
        #     self.outfile = open(rtc_filename, 'a')
        #     self.outfile.write("\n"+json.dumps(request_content_obj)+'\n')

        """
            To write out the response content into right format file
        """
        if rec_flag:
            # TODO: transfer string to bytes
            rec_filename = str(session_id)+'_response_content'
            self.string2bytes_format(
                file_suffix, rec_filename, response_content)
            """
                here for debugging
            """
            # rec_file = str(session_id)+'_response_content.json'
            # self.outfile = open(rec_file, 'a')
            # self.outfile.write('\n'+json.dumps(response_content_obj)+'\n')
        # back to the root directory of the project
        os.chdir(constant.HOME)
        constant.ID_POOL[ip_address] += 1
        self.lock.release()

    @classmethod
    def string2bytes_format(cls, suffix, filename, string):
        """
            :param suffix: suffix of the file
            :param filename: str
            :param string: str that contains bytes information
            transfer string to bytes, and store it in the right file
        """
        if not suffix == '':
            filename = filename+suffix
        i = 0
        with open(filename, 'wb+') as fstb:
            while i < len(string):
                if string[i] == "\\":
                    if string[i+1] == 'x':
                        number = int(string[i+2:i+4], 16)
                        fstb.write(number.to_bytes(1, 'little'))
                        i += 4
                    elif constant.DICTION.__contains__(string[i+1]):
                        number = constant.DICTION[string[i+1]]
                        fstb.write(number.to_bytes(1, 'little'))
                        i += 2
                    else:
                        fstb.write(bytes(string[i], 'utf-8'))
                        i += 2
                else:
                    fstb.write(bytes(string[i], 'utf-8'))
                    i += 1

    @staticmethod
    def load(loader):
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
            Determine the destination type and path, initialize the output
            transformation rules.
        """
        self.encode = ctx.options.dump_encodecontent
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


addons = [JSONDumper()]
