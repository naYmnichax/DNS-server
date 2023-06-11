import socket
import time
import sys

LOCAL_HOST = '127.0.0.1'
LOCAL_PORT = 53
REMOTE_HOST = '192.168.10.1'
REMOTE_PORT = 53
FILE_NAME = './cache'
_cache_dict = {}
_DEBUG = True
ttl = bytes()
create_time = time.time()


def update_cache():
    """ Функция для загрузки кэша из файла при остановке работы сервера """

    with open(FILE_NAME, 'rb') as cache_file:
        answers = [answer.decode().split('$') for answer in cache_file]
    for key, response, time_to_live in answers:
        if float(time_to_live) > time.time():
            _cache_dict[key] = response
            print(_cache_dict.keys())


def receive_from(_socket):
    """
    Функция принимает как аргумент объект типа socket.
    Если ни каких данных не пришло, будем возвращать пустые данные
    """
    _socket.settimeout(1)
    try:
        data, address = _socket.recvfrom(512)
    except:
        data = ''
        address = ('', 0)
        return data, address
    return data, address


def byte_in_bit(_byte):
    tmp = []
    for i in range(8):
        if _byte & (1 << (7 - i)):
            tmp.append(1)
        else:
            tmp.append(0)
    return tmp


def dns_receive_remote(local_buffer, local_addr, remote_socket):
    """
    Передаем данные, которые получили локально, адрес отправителя, и сокет для отправки данных.
    Замечание: у нас есть два сокета. Один для получения данных от пользователей и отправки ему, другой для отправки DNS сервер и получения данных от него.
    """

    if len(local_buffer) and len(local_addr[0]):
        try:
            remote_socket.sendto(local_buffer, (REMOTE_HOST, REMOTE_PORT))
        except:
            print('[!]Can not send DNS to remote.')
        remote_buffer, remote_addr = receive_from(remote_socket)
        if len(remote_buffer):
            return remote_buffer
    return None


def memoize(func):
    """ Декоратов для обработки кеша запроса функции."""

    def wrapper(*args, **kwargs):
        name = func.__name__
        dns_not_id_header = args[0][2:]
        _id = args[0][:2]
        key = (name, dns_not_id_header, frozenset(kwargs.items()))
        if key in _cache_dict:
            if _cache_dict[key] is not None:
                print('~~~~~~~~~~~~~~~~~~~~ Ответ из Кэша ~~~~~~~~~~~~~~~~~~~')
                print(f'[*] Значение кэша: {_cache_dict[key]}')
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                return _id + _cache_dict[key]
        result = func(*args, **kwargs)
        if result is not None:
            if dns_response(result):
                _cache_dict[key] = result[2:]
                with open(FILE_NAME, 'ab') as cache_file:
                    cache_file.write(
                        f'{key} $ {_cache_dict[key]} $ {int.from_bytes(ttl, sys.byteorder) + create_time}\n'.encode('utf-8'))
        return result

    return wrapper


def dns_request(package, _DEBUG=False):
    """ Парсинг структуры секции запроса """
    ID = package[0:2]
    tmp = byte_in_bit(package[2])
    QR = tmp[0]
    RD = tmp[-1]
    QD_COUNT = package[4:6]
    AN_COUNT = package[6:8]
    NS_COUNT = package[8:10]
    AR_COUNT = package[10:12]
    if _DEBUG:
        print(package)
        print('ID session ', ID)
        print('QR = ', QR, 'RD = ', RD)
        print('QD_COUNT ', conversion_from_bytes(QD_COUNT))
        print('AN_COUNT', conversion_from_bytes(AN_COUNT))
        print('NS_COUNT', conversion_from_bytes(NS_COUNT))
        print('AR_COUNT', conversion_from_bytes(AR_COUNT))
    tmp = byte_in_bit(package[12])
    if tmp[0] == 0:
        if _DEBUG:
            print('[*]Normal mark')
        len_mark = '0b'
        for i in range(2, 8):
            len_mark += str(tmp[i])
        len_mark = int(len_mark, 2)
        domain = []
        marker = 13 + len_mark
        domain.append(package[13:marker].decode('utf-8'))
        len_mark = int(package[marker])
        while True:
            if len_mark != 0:
                marker += 1
                domain.append(package[marker:marker + len_mark]
                              .decode('utf-8'))
                marker += len_mark
                len_mark = int(package[marker])
            elif len_mark == 0:
                marker += 1
                break
        Q_TYPE = package[marker + 1:marker + 2]
        marker += 2
        Q_CLASS = package[marker + 1:marker + 2]
        if _DEBUG:
            print(*reversed(domain), sep='.')
            if Q_TYPE:
                print('Q_TYPE A type')
            elif Q_TYPE == 15:
                print('Q_TYPE MX type')
            elif Q_TYPE == 2:
                print('Q_TYPE NS type')
            if Q_CLASS:
                print('Q_CLASS IN type \n')
            else:
                print('Q_CLASS unknown type \n')


def dns_response(package, _DEBUG=False):
    """ Парсинг структуры секции ответов """
    global ttl, create_time
    ID = package[0:2]
    if _DEBUG:
        print(package)
        print('ID session ', conversion_from_bytes(ID))
    tmp = byte_in_bit(package[2])
    QR = tmp[0]
    RD = tmp[-1]
    TC = tmp[6]
    QD_COUNT = package[4:6]
    AN_COUNT = package[6:8]
    NS_COUNT = package[8:10]
    AR_COUNT = package[10:12]
    tmp_rcode = byte_in_bit(package[3])
    RCODE = '0b'
    for i in range(4, 8):
        RCODE += str(tmp_rcode[i])
    RCODE = int(RCODE, 2)
    if RCODE == 0:
        if _DEBUG:
            print('[*] RCODE 0')
    else:
        print('[!] RCODE error')
        return False
    if _DEBUG:
        print('QD_COUNT ', conversion_from_bytes(QD_COUNT))
        print('AN_COUNT', conversion_from_bytes(AN_COUNT))
        print('NS_COUNT', conversion_from_bytes(NS_COUNT))
        print('AR_COUNT', conversion_from_bytes(AR_COUNT))
    tmp = byte_in_bit(package[12])
    if tmp[0] == 0:
        if _DEBUG:
            print('[*]Normal mark')
        len_mark = '0b'
        for i in range(2, 8):
            len_mark += str(tmp[i])
        len_mark = int(len_mark, 2)
        domain = []
        marker = 13 + len_mark
        domain.append(package[13:marker].decode('utf-8'))
        len_mark = int(package[marker])
        while True:
            if len_mark != 0:
                marker += 1
                domain.append(package[marker:marker + len_mark]
                              .decode('utf-8'))
                marker += len_mark
                len_mark = int(package[marker])
            elif len_mark == 0:
                marker += 1
                break
        Q_TYPE = package[marker + 1:marker + 2]
        marker += 2
        Q_CLASS = package[marker + 1:marker + 2]
        marker += 2
        if _DEBUG:
            print(*reversed(domain), sep='.')
            if Q_TYPE:
                print('Q_TYPE A type')
            elif Q_TYPE == 15:
                print('Q_TYPE MX type')
            elif Q_TYPE == 2:
                print('Q_TYPE NS type')
            if Q_CLASS:
                print('Q_CLASS IN type')
            else:
                print('Q_CLASS unknown type')
        tmp = byte_in_bit(package[marker])
        if tmp[0] == 1:
            if _DEBUG:
                print('[*] Compressed label')
            len_mark = '0b'
            for i in range(2, 8):
                len_mark += str(tmp[i])
            marker += 1
            tmp = byte_in_bit(package[marker])
            for i in range(8):
                len_mark += str(tmp[i])
            len_mark = int(len_mark, 2)
            tmp_marker = len_mark
            tmp = byte_in_bit(package[len_mark])
            if tmp[0] == 0:
                len_mark = '0b'
                for i in range(2, 8):
                    len_mark += str(tmp[i])
                len_mark = int(len_mark, 2)
                domain = []
                tmp_marker += 1
                domain.append(package[tmp_marker:tmp_marker + len_mark]
                              .decode('utf-8'))
                tmp_marker = tmp_marker + len_mark
                len_mark = int(package[tmp_marker])
                while True:
                    if len_mark != 0:
                        tmp_marker += 1
                        domain.append(package[tmp_marker:tmp_marker + len_mark]
                                      .decode('utf-8'))
                        tmp_marker += len_mark
                        len_mark = int(package[tmp_marker])
                    elif len_mark == 0:
                        marker += 1
                        break
                if _DEBUG:
                    print(*reversed(domain), sep='.')
                Q_TYPE = package[marker + 1:marker + 2]
                marker += 2
                Q_CLASS = package[marker + 1:marker + 2]
                marker += 2
                if _DEBUG:
                    if Q_TYPE:
                        print('Q_TYPE A type')
                    elif Q_TYPE == 15:
                        print('Q_TYPE MX type')
                    elif Q_TYPE == 2:
                        print('Q_TYPE NS type')
                    if Q_CLASS:
                        print('Q_CLASS IN type')
                    else:
                        print('Q_CLASS unknown type')
                TTL = package[marker:marker + 4]
                ttl = TTL
                create_time = time.time()
                marker += 4
                if _DEBUG:
                    print('TTL :', TTL)
    if TC == 0:
        return True
    else:
        print('TC :', TC)
        return False


def conversion_from_bytes(flag):
    return int.from_bytes(flag, sys.byteorder)


def server_loop(local_host, local_port):
    global _DEBUG
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server.bind((local_host, local_port))
    except:
        print("[!!] Failed to listen on %s:%d" % (local_host, local_port))
        print("[!!] Check for other listening sockets or correct permissions.")
    print("[*] Listening on %s:%d" % (local_host, local_port))
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    update_cache()
    cache = memoize(dns_receive_remote)
    while True:
        local_buffer, local_addr = receive_from(server)
        remote_buffer = cache(local_buffer, local_addr, remote_socket)
        if remote_buffer is not None:
            server.sendto(remote_buffer, local_addr)
            # для просмотра, что всё отработало корректно
            if _DEBUG:
                print('Read localhost %d bytes' % len(local_buffer))
                dns_request(local_buffer, _DEBUG=True)
                dns_response(remote_buffer, _DEBUG=True)
                _DEBUG = False


server_loop(LOCAL_HOST, LOCAL_PORT)
