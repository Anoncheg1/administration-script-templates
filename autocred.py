#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import configparser as cp
import cx_Oracle
import datetime
import email
import imaplib
import logging
import re
import requests
import shutil
import smtplib
import time
import sys
import tempfile
import os

from email.header import decode_header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from os.path import basename
from requests.auth import HTTPBasicAuth
from sys import argv, exit, stdout
from zipfile import ZipFile

LOCKFILE = '.Lock'


def init_logger(level, logfile_path: str = None):
    """
    stderr  WARNING ERROR and CRITICAL
    stdout < DEBUG, INFO

    :param logfile_path:
    :param level: level for stdout
    :return:
    """

    formatter = logging.Formatter('autocred [%(asctime)s] %(levelname)-6s %(message)s')
    logger = logging.getLogger(__name__)
    logger.setLevel(level)  # debug - lowest
    # log file
    if logfile_path is not None:
        h0 = logging.FileHandler(logfile_path)
        h0.setLevel(level)
        h0.setFormatter(formatter)
        logger.addHandler(h0)
    # stdout -- python3 script.py 2>/dev/null | xargs
    h1 = logging.StreamHandler(sys.stdout)
    h1.setLevel(level)  # level may be changed
    h1.addFilter(lambda record: record.levelno < logging.WARNING)  # (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    h1.setFormatter(formatter)
    # stderr -- python3 script.py 2>&1 >/dev/null | xargs
    h2 = logging.StreamHandler(sys.stderr)
    h2.setLevel(logging.WARNING)  # fixed level
    h2.setFormatter(formatter)

    logger.addHandler(h1)
    logger.addHandler(h2)
    return logger


def config_load(filename='config.conf'):
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(script_dir, filename)
        config = cp.ConfigParser()
        config.read(path)
        params = dict()
        for section in config.sections():
            params[section] = {}
            for item in config.items(section):
                params[section][item[0]] = item[1]
        if not params:
            log.exception(u'Ошибка парсинга конфигурационного файла!')
            return None
        else:
            return params
    except:
        log.exception(u'Ошибка парсинга конфигурационного файла!')
        return None


def folder_size(folder_path: str):
    size = 0
    for path, dirs, files in os.walk(folder_path):
        for f in files:
            pf = os.path.join(path,f)
            size += os.stat(pf).st_size
    return size


def create_or_remove_tmp_dir(path, action='create'):
    path = path + 'tmp'
    try:
        os.mkdir(path) if action == 'create' else os.rmdir(path)
    except OSError as e:
        log.exception(u'%s of the directory failed' % action)
        return None
    return path


def lock_folder(path):
    lock_path = '{}/{}'.format(path, LOCKFILE)
    if os.path.exists(lock_path) and os.path.isfile(lock_path):
        log.warning(u'Папка %s уже заблокирована' % path)
        return False
    try:
        #        os.mknod(lock_path)
        open(lock_path, 'w+').close()
        log.debug(u'Папка %s успешно заблокирована' % path)
    except IOError as e:
        log.exception(u'Папка %s не может быть заблокирована!' % path, e)
        return None
    else:
        return True


def unlock_folder(path):
    lock_path = '{}/{}'.format(path, LOCKFILE)
    if os.path.exists(lock_path) and os.path.isfile(lock_path):
        try:
            os.remove(lock_path)
        except OSError as e:
            log.exception(u'Папка %s не может быть разблокирована!' % path, e)
            return None
        else:
            return True
    log.warning(u'Папка %s уже разблокирована' % path)
    return False


def cleanup_folder(path, exclude=None):
    if os.path.exists(path) and os.path.isdir(path):
        f_list = os.listdir(path)
        for f in f_list:
            try:
                if exclude:
                    if not f.endswith(exclude.lower()) and not f.endswith(exclude.upper()):
                        os.remove(path + '/' + f)
                    else:
                        shutil.move(path + '/' + f, path + '/' + filename_normalization(f))
                else:
                    os.remove(path + '/' + f)
            except OSError as e:
                log.error(u'Ошибка удаления файла %s' % f, e)
                return None
        return True


def archive_file(arc_name, files: list) -> str:
    if files is None or len(files) == 0:
        log.exception(u"Empty list of files for archiving.")
    with zipfile.ZipFile(arc_name, 'w') as zip_obj:
        for f in files:
            log.debug('Архивирую файл: %s' % f)
            zip_obj.write(f, basename(f))
    return arc_name


def extract_file(arc_name, targ_dir):
    with ZipFile(arc_name, 'r') as zip_obj:
        log.debug(u'Распаковка архива: %s' % arc_name)
        zip_obj.extractall(targ_dir)


def sign_file(uri, cert_thumbprint, auth, filename):
    response = requests.post('{}?thumbprint={}&storage=My'.format(uri, cert_thumbprint),
                             files={basename(filename): open(filename, 'rb')}, auth=auth, timeout=5)
    if response.status_code == requests.codes.ok:
        with open(filename + '.sig', 'wb') as fd:
            for chunk in response.iter_content(chunk_size=128):
                fd.write(chunk)
        return [filename, filename + '.sig']
    else:
        log.error(u'Ошибка ответа от сервиса ЭЦП: %s' % response.status_code)
        return None


def encrypt_file(uri, cert_thumbprint, auth, filename):
    response = requests.post('{}?thumbprint={}&storage=AddressBook'.format(uri, cert_thumbprint),
                             files={basename(filename): open(filename, 'rb')}, auth=auth, timeout=5)
    if response.status_code == requests.codes.ok:
        with open(filename + '.enc', 'wb') as fd:
            for chunk in response.iter_content(chunk_size=128):
                fd.write(chunk)
        return filename + '.enc'
    else:
        log.error(u'Ошибка ответа от сервиса шифрования: %s' % response.status_code)
        return None


def decrypt_file(uri, cert_thumbprint, filename):
    """ side effect auth"""
    try:
        auth = HTTPBasicAuth(c['api']['user'], c['api']['pass'])
        with open(filename, 'rb') as f:
            response = requests.post('{}?thumbprint={}&storage=My'.format(uri, cert_thumbprint),
                                     files={basename(filename): f}, auth=auth, timeout=15)
            # retry after 10s-10m, 30 tryes.
        for i, _ in enumerate(range(30)):
            if response.status_code == 500:
                log.warning(u'Ошибка %s от сервиса расшифрования, попытка %s ' % (response.status_code, i))
                log.info(u'Повторная попытка через: %s sec' % int(10 * (i + 1)))
                time.sleep(10 * (i + 1))
                auth = HTTPBasicAuth(c['api']['user'], c['api']['pass'])
                with open(filename, 'rb') as f:
                    response = requests.post('{}?thumbprint={}&storage=My'.format(uri, cert_thumbprint),
                                             files={basename(filename): f}, auth=auth, timeout=15)
    except:
        log.exception(u'Ошибка при открытии файла %s' % filename)

    if response.status_code == requests.codes.ok:
        filename = '{}.{}'.format(filename.split('.')[0], filename.split('.')[1])
        with open(filename, 'wb') as fd:
            for chunk in response.iter_content(chunk_size=128):
                fd.write(chunk)
        return filename
    else:
        log.error(u'Ошибка ответа от сервиса расшифрования: %s ' % response.status_code)
        return False


def send_mail(username, password, send_from, send_to, subject,
              text, files=None, server="mx1.rnb.com"):
    assert isinstance(send_to, list)

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(text))

    for f in files or []:
        with open(f, "rb") as fil:
            part = MIMEApplication(
                fil.read(),
                Name=basename(f)
            )
        # After the file is closed
        part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
        msg.attach(part)

    smtp = smtplib.SMTP(server)
    smtp.login(username, password)
    log.debug(u'Отправляю письмо на %s' % send_to)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()


def downloaAttachmentsInEmail(m, emailid, outputdir):
    resp, data = m.fetch(emailid, "(BODY.PEEK[])")
    email_body = data[0][1].decode('ascii')
    # print(email_body.decode('ascii'))
    mail = email.message_from_string(email_body)
    if mail.get_content_maintype() != 'multipart':
        return
    for part in mail.walk():
        if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
            filename, _ = decode_header(part.get_filename())[0]
            log.debug("decode filename " + str(filename))
            if isinstance(filename, bytes):
                filename = filename.decode('utf-8')
            if not re.search(r'^\d{8}_FDEBT[0-9]?\.zip\.enc$', filename):
                continue
            with open('{}/{}'.format(outputdir, filename), 'wb') as f:
                f.write(part.get_payload(decode=True))


def downloadAllAttachmentsInInbox(server, user, password, outputdir, days_since=0) -> bool:
    """

    :param server:
    :param user:
    :param password:
    :param outputdir:
    :param days_since:
    :return: True if there is attachments else False
    """
    date = datetime.datetime.now() - datetime.timedelta(days=days_since)
    criteria = '(SENTSINCE "{}" HEADER Subject "{}")'.format(date.strftime('%d-%b-%Y'),
                                                             'Reestr platezhej po kreditam RNB')
    m = imaplib.IMAP4(server)
    m.login(user, password)
    m.select()
    resp, items = m.search(None, criteria)
    if not items[0]:
        log.debug('На почтовом сервере Нет писем с реестрами в папке Входящих')
        return False
    items = items[0].split()
    for emailid in items:
        downloaAttachmentsInEmail(m, emailid, outputdir)
        m.store(emailid, '+FLAGS', '\\Seen')
        m.copy(emailid, 'processed')
        m.store(emailid, '+FLAGS', '\\Deleted')
    m.close()
    m.logout()
    return True


def process_out_reestr():
    """ Проблемы - Очищает всею исходящую папку - нужно чтобы отработал как можно быстрее"""
    log.info('Обработка ИСХОДЯЩИХ реестров...')
    out_dir = c['storage']['base_path'] + c['storage']['output']
    tmp_dir = c['storage']['base_path'] + c['storage']['tmp_out']
    # process out dir
    # out_list = find_to_process(out_dir, '.txt')
    out_list = [os.path.join(out_dir, fn) for fn in os.listdir(out_dir) if fn.endswith('.txt')]
    log.info(u'Найдено %s реестра(ов)' % len(out_list))
    # check file time
    for f in out_list:
        if (time.time() - os.stat(f).st_mtime) < 30:  # 30s
            log.info(u'Один из файлов был недавно изменен, попробуем в другой раз')
            continue
        if os.stat(f).st_size == 0:
            log.warning("Пустой исходящий файл: " + f)
            shutil.move(f, os.path.join(c['storage']['base_path'], c['storage']['archive'], basename(f)))
            continue
        f_new = os.path.join(tmp_dir, basename(f))
        shutil.move(f, f_new)
    # process tmp_dir
    # out_list = find_to_process(tmp_dir, '.txt')
    out_list = [os.path.join(tmp_dir, fn) for fn in os.listdir(tmp_dir) if fn.endswith('.txt')]
    if out_list:
        auth = HTTPBasicAuth(c['api']['user'], c['api']['pass'])
        for f in out_list:
            if (time.time() - os.stat(f).st_mtime) < 20:  # 20 sec
                log.info('Файлов {} был недавно изменен, обработаем позже'.format(f))
            #
            log.info(u'Подписываю реестр %s ЭЦП...' % f)
            sf = sign_file(c['api']['sig_uri'], c['api']['sig_cert_thumbprint'], auth, f)
            if not sf:
                log.critical(u'Неустранимая ошибка подписания реестра... продолжение невозможно')
                return None  # do not clean
            #
            log.info(u'Архивирую реестр и ЭЦП перед шифрованием...')
            af = archive_file(f + '.zip', sf)
            #
            log.info(u'Шифрую архив реестра и ЭЦП перед отправкой...')
            ef = encrypt_file(c['api']['enc_uri'], c['api']['enc_cert_thumbprint'], auth, af)
            if not ef:
                log.critical(u"Неустранимая ошибка шифрования реестра... продолжение невозможно")
                return None  # do not clean
            log.info(u'Отправляю на {} зашифрованный архив реестра и ЭЦП...'.format(list(c['recipient'].values())))
            send_mail(c['sender']['login'], c['sender']['password'], c['sender']['address'],
                      list(c['recipient'].values()), subject=basename(ef), text=basename(ef), files=[ef])

            # Send unencrypted files to Ashotovna
            log.info(u'Отправляю незашифрованый реестр %s ' % f)
            send_mail(c['sender']['login'], c['sender']['password'], c['sender']['address'],
                      list(c['recipient_copy'].values()), "Быстробанк автокредиты исходящий. " + basename(f), basename(f), [f])
            # Archiving
            arch_file = os.path.join(c['storage']['base_path'], c['storage']['archive'], basename(f))
            if os.path.isfile(arch_file)  \
                                and (time.time() - os.stat(arch_file).st_mtime) < 60*30:  # <30 min:
                log.warning("Исходящий файл уже есть в архиве. " + basename(f))
            shutil.move(f, arch_file)
        log.debug(u'Очищаю папку от временных файлов')
        cleanup_folder(tmp_dir)  # must be done accurate


def process_in_reestr():
    log.info(u'Загрузка ВХОДЯЩИХ реестров из %s...' % c['sender']['address'])
    dir_in = os.path.join(c['storage']['base_path'], c['storage']['input'])
    dir_tmp_in = os.path.join(c['storage']['base_path'], c['storage']['tmp_in'])
    # with tempfile.TemporaryDirectory() as dir_tmp_in:

    if not downloadAllAttachmentsInInbox(c['imap']['host'], c['imap']['login'], c['imap']['password'],
                                         dir_tmp_in, 0):
        log.debug("Нет входящих файлов")

    in_list = [os.path.join(dir_tmp_in, fn) for fn in os.listdir(dir_tmp_in) if fn.endswith('.zip.enc')]
    # if len(in_list) == 0:
    #     log.error("Входящий файл не .zip.enc! " + str(os.listdir(dir_tmp_in)))

    log.info('Найдено %s реестра(ов)' % len(in_list))
    for f in in_list:
        if (time.time() - os.stat(f).st_mtime) < 30:  # 30s
            log.info(u'Файл %s был недавно изменен, попробуем в другой раз' % basename(f))
            continue
        log.info('Расшифровываю архив %s с реестром и ЭЦП' % basename(f))
        # with retries
        df = decrypt_file(c['api']['dec_uri'], c['api']['dec_cert_thumbprint'], f)
        if not df:
            log.critical("Неустранимая ошибка расшифрования реестра... продолжение невозможно")
            return None
        log.info('Распаковка архива реестра и ЭЦП... ' + df)
        extract_file(df, dir_in)
        os.remove(df)
        os.remove(f)


def isjob_active(host, svc, user, password, port=1521):
    con = cur = row = None
    dsn_string = cx_Oracle.makedsn(host, port, svc)
    try:
        con = cx_Oracle.connect(user=user, password=password, dsn=dsn_string)
        try:
            cur = con.cursor()
            cur.execute("""select count(session_id)
                        from sys.dba_scheduler_running_jobs s,
                        ibs.Z#SYSTEM_JOBS j where j.c_method_class='RNB_BB_CRED_REE'
                        and j.c_short_name in ('JOB_INFO_REE','JOB_TRAN_REE')
                        and s.job_name='J$'||trim(j.ID)""")
            row, = cur.fetchone()
        except cx_Oracle.Error as e:
            log.error(u'ОШИБКА: Выполнения SQL-запроса')
        finally:
            if isinstance(cur, cx_Oracle.Cursor):
                cur.close()
    except cx_Oracle.Error as e:
        log.error(u'ОШИБКА: Проблема соединения с БД Oracle')
    finally:
        if isinstance(con, cx_Oracle.Connection):
            con.close()
    return True if row or row is None else False


def main():
    if lock_folder(c['storage']['base_path']):
        try:
            # CFT lock check
            if not isjob_active(c['cft']['host'], c['cft']['svc'],
                                c['cft']['user'], c['cft']['pass']):
                process_out_reestr()
                process_in_reestr()
        except:
            log.exception('Необработанное исключение')
        finally:
            unlock_folder(c['storage']['base_path'])


if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_file = os.path.join(script_dir, 'autocred.log')  # c['storage']['log_path']
    conf_file = os.path.join(script_dir, 'autocred.conf')
    c = config_load(conf_file)   # USED AS GLOBAL!

    log = init_logger(logging.INFO, log_file)
    main()

    # test
    # log = init_logger(logging.DEBUG)   # USED AS GLOBAL!
    # log.error("awt")
