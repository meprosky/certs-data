#!/usr/bin/env python
# coding: utf-8

#Скрипт читает каталог с сертификатам ключей проверки электронных подписей формата X.509
#ищет в каталоге файлы с расширение .cer, которые должны быть в формате DER
#В многопотоке вытягиваем списки отзыва из точек распространения в структуре сертифика
#проверяем сертификаты по спискам отзыва и дате окончания действия и формируем выходной файл формата excel
#Из-за чехарды с кодировками при формировании сертификатов удостоверяющими центрам приходится преообразовывать 
#разными способами поля сертификатов
#запуск в Windows "python cert-data-mt.py certs-folder-name"


import ssl, OpenSSL, cryptography
import os, fnmatch, re, urllib
import urllib.request
import pandas as pd
from xlsxwriter import Workbook
import urllib.error 
from datetime import datetime
import time, sys
from time import sleep, ctime 
from threading import Thread, Event, Lock
from queue import Queue
import random
import string


# In[14]:


# In[2]:


class Mythread(Thread):
    def __init__(self, func, args, name=''):
        Thread.__init__(self)
        self.name = name
        self.func = func
        self.args = args
    
    def run(self):
        self.func(*self.args)

class Threadpool():
    
    def __init__(self, numthreads):
        self.maxpoolsize = numthreads
        self.poolsize = 0
        self.threadlist = []
        self.completeworks = 0
        
        
    def isfull(self):
        if self.poolsize >= self.maxpoolsize:
            return True
        else:
            return False
       
    def addthread(self, t):
        if self.poolsize < self.maxpoolsize:
            self.poolsize += 1
            self.threadlist.append(t)
            
    def start_and_wait(self):
        
        if self.poolsize == 0:
            print('Pool is empty. No works.')
            return False
        
        for t in self.threadlist:
            t.start()
        
        for t in self.threadlist:
            t.join()

        self.completeworks += 1
        
        self.poolsize = 0
        self.threadlist = []


# In[3]:


global certs_info
global ufr

def main(fn):
    
    t1 = time.monotonic()
    
    print('Multithread ver.')
    
    tpool = Threadpool(1000)
    
    global certs_info
    global ufr

    certs_info = []

    
    for root, dirs, files in os.walk(fn): #'err_cert'):
        for filename in fnmatch.filter(files, '*.cer'):
            fullname = os.path.join(root, filename)
            
            if tpool.isfull():
                tpool.start_and_wait()
            
            t = Mythread(cert_getinfo, (fullname,), cert_getinfo.__name__)
            
            tpool.addthread(t)

    if tpool.poolsize > 0: #если остались невыполненные работы дорабатываем
        tpool.start_and_wait()             

    print('Найдено сертификатов .cer:', len(certs_info))    
    
    url = []

    for x in certs_info:
        url.append(x['CRLurl_1'])
        url.append(x['CRLurl_2'])
        url.append(x['CRLurl_3'])
    
    url = list(set(url))
    url.remove('')
    
    print('Точек распространения crl:', len(url))

    urld = {}
    
    #формируем имена crl файлов
    for x in url:
        a = re.findall(r'[^/]+crl', x) #имя crl  файла
        filename = a[0] + '.' + generate_random_string(4) + '.crl'
        urld.update({x:filename})
    
    tpool = Threadpool(1000) 
    
    #global urldres
    
    urldres = {}
    
    print('Загрузка crl...')
    
    for key, val in urld.items():
        if tpool.isfull():
            tpool.start_and_wait()
        t = Mythread(load_crl_file, (key, val, urldres,), load_crl_file.__name__)
        tpool.addthread(t)

    if tpool.poolsize > 0: #если остались невыполненные работы дорабатываем
        tpool.start_and_wait()             
    
    print('Загружено crl:', sum(1 for x in urldres.values() if x['status'] == 'crl_loaded'))
    
    
    #можно было сдлать в потоках, но тогда вызов
    #crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, open(crlfile, 'rb').read())
    #то выдает то не выдает ошибку 
    #for key, val in urldres.items():
    #    process_crl_file(key, urldres)
    
    ufr = urldres

    tpool = Threadpool(1000) 
   
    print('Проверка на отзыв...')

    for cert in certs_info:
        if tpool.isfull():
            tpool.start_and_wait()
        t = Mythread(verify_cert_crl, (cert, urldres), verify_cert_crl.__name__)
        tpool.addthread(t)

    if tpool.poolsize > 0: #если остались невыполненные работы дорабатываем
        tpool.start_and_wait()             
    
    print('Проверено сертификатов:', len(certs_info))
    
    #удаляем временные crl файлы
    for key, val in urldres.items():
        try:
            os.remove(urldres[key]['file'])
        except:
            pass
    
    filexlsx = 'certs_multithread.xlsx'
    print('Запись результатов в файл:', filexlsx)   
    write_dict_in_xls(filexlsx, certs_info)
    print('Завершено.')
    
    t2 = time.monotonic()
    
    print('Время работы: {0:.2f}'.format(t2-t1))
     


# In[4]:


#print('{0:.2f} ddd'.format(2.333))


# In[5]:


def get_crl_extension_number(cert): #получить номер свойства "точек отзыва" в доп. свойстах сертификата
    for x in range(0, cert.get_extension_count()):
        ext = cert.get_extension(x)
        if ext.get_short_name() == b'crlDistributionPoints':
            return x
       
    return -1

def get_crl_points_url(cert): #выделить адреса URL "точек отзыва"
    n = get_crl_extension_number(cert)
    if n == -1:
        return ['', '', '']
    
    crl_points = cert.get_extension(n).get_data()    
    crl_points_str = crl_points.decode(encoding='utf-8', errors='ignore')
    crl_points_list = re.findall(r'https?:.+?\.crl', crl_points_str)
    
    crl_points_list = crl_points_list + [''] * (3 - len(crl_points_list))
     
    return crl_points_list


# In[6]:


def decode_from_utf16be_utf8(bs): #декодировать байты в utf-16 или utf-8
    return bs.decode('utf-16be', 'ignore') if bs.count(0x4) > 2 else bs.decode('utf-8', 'ignore')   

def correct_negative_serial_number(sn):
    s = '0b'
    a = 256 - sn.bit_length()
    s = s + a * '1'
    #print(s)
    for x in bin(sn)[3:]:
        if x == '1':
            s = s + '0'
        else:
            s = s + '1'
    
    return int(s, 2) + 1


# In[7]:


def load_cer(filename): #прочитать сертификат из файла формата CER, преобразовать в  PEM
    
    f = open(filename, "rb")
    der = f.read()
    f.close()
    
    try:
        pemc = ssl.DER_cert_to_PEM_cert(der)   
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pemc) 
    except:
        #print('Error reading cert!!!')
        return -1, -1
    
    result = {
        'subject': dict(x509.get_subject().get_components()),
        'issuer': dict(x509.get_issuer().get_components()),
        'serialNumber': x509.get_serial_number(),
        'version': x509.get_version(),
        'notBefore': datetime.strptime(x509.get_notBefore().decode(), '%Y%m%d%H%M%SZ'),
        'notAfter': datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ'),
        'CRLs': get_crl_points_url(x509)
    }
    
    return result, x509    


# In[8]:


def cert_getinfo(filename):
    
    global certs_info
    
    cert, x509 = load_cer(filename)
        
    if cert == -1: #ошибка чтения сертификата
        cer1 = {'Файл':filename,
                'Серийный номер':'ERROR READING CERT', 
                'Дата проверки': datetime.today().strftime('%d.%m.%Y'),
                'Действителен с': '', 
                'по':'', 
                'Издатель': '',
                'Владелец': '',
                'Орг. владельца': '',
                'SN': '',
                'ИНН': '',
                'СНИЛС': '',
                'ОГРН': '',
                'Статус сертификата': '',
                'CRLurl_1': '',
                'CRLurl_2': '', 
                'CRLurl_3': '',
                'CRL status': '',
                'CRL updated': '', 'snraw': ''}
        
        certs_info.append(cer1)
        return
        
    
    subject = cert['subject']
    issuer = cert['issuer']
    sn = cert['serialNumber']
    
    #print(sn)
    
    if int(sn) < 0:    #если сер. номер отрицательный треб. преообразование к "сырым" двоичным данным
        sn = correct_negative_serial_number(sn)
        #sn = sn & (2 ** sn.bit_length() - 1)
      
    
    sn_text_hex = "{:02x}".format(sn)

    if len(sn_text_hex) % 2 :
        sn_text_hex = '0' + sn_text_hex

    sn_text_hex = (''.join([x+y+' ' for x, y in zip(sn_text_hex[::2], sn_text_hex[1::2])])).strip()
    date_from = cert['notBefore']
    date_to = cert['notAfter']
    tnow = datetime.today()
        
    status_date = 'ИСТЕК' if date_to < tnow else 'ДЕЙСТВ'
        
    subj_CN = subject[b'CN']
    iss_CN = issuer[b'CN']
        
    subj_INN = subject[b'INN'] if b'INN' in subject else ''
    subj_INN = subj_INN if type(subj_INN) == str else subj_INN.decode('utf-8')
    
    subj_SNILS = subject[b'SNILS'] if b'SNILS' in subject else ''
    subj_SNILS = subj_SNILS if type(subj_SNILS) == str else subj_SNILS.decode('utf-8')
    
    subj_OGRN = subject[b'OGRN'] if b'OGRN' in subject else ''
    subj_OGRN = subj_OGRN if type(subj_OGRN) == str else subj_OGRN.decode('utf-8')
                
        
    name2 = decode_from_utf16be_utf8(subject[b'SN']) if b'SN' in subject else ''
    name3 = decode_from_utf16be_utf8(subject[b'GN']) if b'GN' in subject else ''
    name2 = name2 + (' ' if name3 != '' else '') + name3
        
    crl_url = cert['CRLs']
    
    #status_crl, crl = verify_cert_CRL(sn, crl_url) 
    #status_crl, crl = '', ''
        
    #status_date = status_date + ',ОТОЗВАН' if status_crl == 'REVOKED' else status_date
    
        
    cer1 = {'Файл':filename,
            'Серийный номер':sn_text_hex, 
            'Дата проверки': tnow.strftime('%d.%m.%Y'),
            'Действителен с': date_from.strftime('%d.%m.%Y'),
            'по':date_to.strftime('%d.%m.%Y'),
            'Издатель': decode_from_utf16be_utf8(iss_CN),
            'Владелец': decode_from_utf16be_utf8(subj_CN),
            'Орг. владельца': decode_from_utf16be_utf8(subject[b'O']) if b'O' in subject else '',
            'SN': name2,
            'ИНН': subj_INN,
            'СНИЛС': subj_SNILS,
            'ОГРН': subj_OGRN,
            'Статус сертификата': status_date,
            'CRLurl_1': crl_url[0],
            'CRLurl_2': crl_url[1],
            'CRLurl_3': crl_url[2],
            'CRL status': 'wait',
            'CRL updated': 'unknown',
            'snraw': sn}
    
    certs_info.append(cer1)
        
    #print('Файл:', certinfodict['Файл'])
    #print('Владелец:', certinfodict['Владелец'])
    #print('SN:', certinfodict['SN'])
    #print('\n')
    #return x509, certinfodict


# In[9]:


def load_crl_file(url, crlfile, urlcrldict):
   
    try:
        
        urllib.request.urlretrieve(url, crlfile)
        
        crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, open(crlfile, 'rb').read())
        crt = crl.to_cryptography()
        crl_lastupdate = crt.last_update.strftime('%d.%m.%Y')
        
        #urlcrldict.update({url:{'file':crlfile, 'status':'crl_loaded', 'crldata':'wait', 'lastupdate':'wait'}})
        
        urlcrldict.update({url:{'file':crlfile, 'status':'crl_loaded', 'crldata':crt, 'lastupdate':crl_lastupdate}})
    
    except urllib.error.HTTPError as e:
        urlcrldict.update({url:{'file':crlfile, 'status':'load_error', 'crldata':'none', 'lastupdate':'unknown'}})
        #print('Error load crl', url)
        #status = 'CRL receiving ERROR\n' + str(e.__dict__)
    
    except urllib.error.URLError as e:
        urlcrldict.update({url:{'file':crlfile, 'status':'load_error', 'crldata':'none', 'lastupdate':'unknown'}})
        #print('Error load crl', url)
        #status = 'CRL receiving ERROR\n' + str(e.__dict__)


# In[10]:


def process_crl_file(url, urlcrldict):
    try:
        cd = urlcrldict[url]
        crlfile = cd['file']
        
        crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, open(crlfile, 'rb').read())
        crt = crl.to_cryptography()
        crl_lastupdate = crt.last_update.strftime('%d.%m.%Y')
        
        cd['crldata'] = crt
        cd['lastupdate'] = crl_lastupdate
     
    except:
        print('process_crl_file error', url, crlfile)
        cd['crldata'] = 'crt_error'
        cd['lastupdate'] = 'unknown'
 


# In[ ]:





# In[11]:


def verify_cert_crl(cert, urlres):

    sn = cert['snraw']
    
    u1 = cert['CRLurl_1']
    u2 = cert['CRLurl_2']
    u3 = cert['CRLurl_3']
    
    res = 'crlurl_empty'
    crl_lastupdate = 'unknown'

    for x in [u1, u2, u3]:
        
        
        if x == '':
            continue
        else:
            cd = urlres[x]
            
            crl_data = cd['crldata']
            crl_lastupdate = cd['lastupdate']
            crl_loadstatus = cd['status']
            
            if crl_data == 'none':
                res = 'crldata_none'
                crl_lastupdate = 'unknown'
                continue        
            elif crl_loadstatus == 'load_error':
                res = 'crl_load_error'
                crl_lastupdate = 'unknown'
            else:
                res = 'OK (none in CRL)' if crl_data.get_revoked_certificate_by_serial_number(sn) is None                                          else 'REVOKED'
                break
    
    sta = cert['Статус сертификата']
    
    if res == 'REVOKED':
        cert['Статус сертификата'] = sta + ',ОТОЗВАН'
   
    cert['CRL status'] = res
    cert['CRL updated'] = crl_lastupdate
 


# In[12]:


def generate_random_string(length):
    letters = string.ascii_lowercase + string.digits
    rand_string = ''.join(random.choice(letters) for i in range(length))
    #print("Random string of length", length, "is:", rand_string)
    return rand_string


# In[13]:


def write_dict_in_xls(file, certs): #записать словарь в таблицу excel
    if certs == []:
        print('Certs list is empty, nothing write to XLSX')
        return -1
    
    ordered_list = [*certs[0].keys()]
    wb = Workbook(file)
    ws = wb.add_worksheet("New Sheet")
    first_row = 0

    for header in ordered_list:
        col = ordered_list.index(header) # we are keeping order.
        ws.write(first_row,col,header)
    
    row = 1
    for record in certs:
        for key, value in record.items():
            col = ordered_list.index(key)
            ws.write(row, col, str(value))
        row += 1 #enter the next row

    wb.close()


fn = sys.argv[1]

if os.path.isdir(fn):
    
    main(fn)        

elif os.path.isfile(fn):
    
    cert_info, x509 = cert_getinfo(fn)
    
    if x509 == -1:
        print('Error reading cert!!!')
    else:
        for key, value in cert_info.items():
            print(key + ':', value)
    
        print('\nSubjec - full info\n')
    
        for x in x509.get_subject().get_components():
            print(decode_from_utf16be_utf8(x[0]), ':', decode_from_utf16be_utf8(x[1]))
    
        print('\nIssuer - full info\n')
    
        for x in x509.get_issuer().get_components():
            print(decode_from_utf16be_utf8(x[0]), ':', decode_from_utf16be_utf8(x[1]))
else:
    print('No certs for verify!')





