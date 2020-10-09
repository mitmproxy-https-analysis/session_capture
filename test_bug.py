# 将类似于\n这种string转成bytes，处理非\x85(\x+两位数字)的情况
DICTION = {'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13,
           't': 9, 'v': 11, "'": 39, '"': 34, '?': 63, '0': 0}

"""这个脚本对于转换图片非常OK, 但是对于转换https不太行"""


"""
secondsubfile: 文件后缀名
filename: 文件名
string: 传进来的二进制的string流
"""


def string2bytes_format(secondsubfile, filename, string):
    if secondsubfile == 'others':
        return
    i = 0
    # 这里是主要写入的，secondsubfile 是为了文件夹分类
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
