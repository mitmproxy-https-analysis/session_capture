import hashlib
import psycopg2
import time
import json
import os

class PGConnect:
    def __init__(self, host="localhost", port=5432, user="checker", password="lsl213", database="inno"):
        self._host: str = host
        self._port: int = port
        self._user: str = user
        self._password: str = password
        self._database: str = database
        self._connection = psycopg2.connect(host=host, port=port, user=user, password=password, database=database)
        self._cursor = self._connection.cursor()
        self._insert_sql = '''
        insert into detection_info (md5,conclusion,details) values (%(md5)s,%(conclusion)s,%(details)s)
        '''
        self._select_sql = "select * from detection_info where md5=%(md5)s"
        self._result_set = None

    def insert_statement(self, details: dict):
        try:
            self._cursor.execute(self._insert_sql,
                                 {'md5': details['md5'], 'conclusion': details['conclusion'], 'details': str(details)})
        except psycopg2.errors.UniqueViolation:
            pass
        finally:
            self._connection.commit()

    def create_table(self):
        self._cursor.execute(
            '''
            create table "detection_info"(
            id bigserial primary key,
            md5 varchar unique,
            conclusion text,
            details text
            )
            ''')
        self._cursor.execute(
            '''
            create index md5_index on detection_info(md5)
            ''')
        self._connection.commit()

    def sel_statement(self, md5: str):
        self._cursor.execute(self._select_sql, {'md5': md5})
        self._result_set = self._cursor.fetchall()

    def get_result_set(self):
        if len(self._result_set) != 0:
            return json.loads(self._result_set[0][3].replace('\'', '"'))
        else:
            return None

    def close_connection(self):
        self._connection.close()

    def establish_connection(self):
        self._connection = psycopg2.connect(host=self._host, port=self._port, user=self._user, password=self._password,
                                            database=self._database)
        self._cursor = self._connection.cursor()


if __name__ == '__main__':
    st = time.time()
    pg = PGConnect(host="localhost", port=5432, user="checker", password="lsl213", database="inno")
    print(time.time() - st)
    iteration = 100
    total = 0
    for i in range(iteration):
        s = time.time()
        pg.sel_statement('9880073ccd3492fb78c913df2a91a696')
        rst = pg.get_result_set()
        v = time.time()
        total += v - s
        if rst is None:
            ## TODO: 请求
            print('nothing in the database....')
            pass
        else:
            print(rst)

    print(total / iteration)
    # s = json.loads(rst[0][3].replace('\'', '"'))
    # print(dict(rst[0][3]))
    # print(type(s))
    # print(len(rst))
    pg.close_connection()
    pg.establish_connection()
    pg.sel_statement('9880073ccd3492fb78c913df2a91a695')
