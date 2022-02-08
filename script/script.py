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

    try:
        smtp.login(username, password)
        log.debug('Отправляю письмо на %s' % send_to)
        smtp.sendmail(send_from, send_to, msg.as_string())
    except Exception as e:
        raise type(e)(str(e) + " happen. Fail to send email!").with_traceback(sys.exc_info()[2])
    finally:
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


def remove_to_archive_sftp(filename_orig, sftp_folder) -> bool:
    """
    move filename_orig to sftp_folder/ARCHIVE/
    :param filename_orig:
    :param sftp_folder:
    :return:
    """
    # -- REMOVE FROM SFTP ARCHIVE SFTP
    filename_orig_escaped = filename_orig.replace(' ', '\\ ')
    command = 'echo -e rename \"' + filename_orig_escaped + '\" \"ARCHIVE/' + filename_orig_escaped + \
              '\""\nquit\n" | sshpass -f ' + pass_path + ' ' + \
              'sftp -v -oUser=rnb ftp.banksoyuz.ru:"' + sftp_folder + '" > /dev/null 2>&1'
    log.debug(command)
    t = Timer(SSH_DELAY, timeout, ("SFTP Connection timeout",))
    t.start()
    res = os.system(command)  # "-i .ssh/openssh_key drop2.mkb.ru:rusnarbank/prod/in > /dev/null 2>&1")
    t.cancel()
    return res == 0



def process_out(target_remote_dir: str, out_path: str, email_is_special: bool = False):
    log.info('Обрабатываю ИСХОДЯЩИЕ ' + str(out_path))
    # -- check big files and split it to tmp system folder
    for i, filename in enumerate(os.listdir(out_path)):
        file_path_orig = os.path.join(out_path, filename)
        if filename == 'tmp' or filename == '.hidden' or filename == 'MOVED':
            continue
        # check last modified
        if os.path.isdir(file_path_orig):
            for f_name in os.listdir(file_path_orig):
                f_path = os.path.join(file_path_orig, f_name)
                if (time.time() - os.stat(f_path).st_mtime) < 60 * 10:  # 10 m
                    log.info('Директория {} была недавно изменена, обработаем позже'.format(filename))
                    continue
        else:
            if (time.time() - os.stat(file_path_orig).st_mtime) < 60*10:  # 10 m
                log.info('Файлов {} был недавно изменен, обработаем позже'.format(filename))
                continue
        # check size
        if os.path.isdir(file_path_orig):
            siz = folder_size(file_path_orig) / 1000 / 1000  # M
        else:
            siz = os.stat(file_path_orig).st_size / 1000 / 1000  # M
        if siz > 500:  # split big file > 500 MB
            tmp_file = os.path.join(c['storage']['out_big_path'], filename).replace(' ', '_')
            command = f'7za -mx=3 -v{SPLIT_7z_SIZE}m a "{tmp_file}.7z" "{file_path_orig}" > /dev/null 2>&1'
            log.debug(command)
            t = Timer(SSH_DELAY*10, timeout, ("7za split timeout",))
            t.start()
            res = os.system(command)
            t.cancel()
            if res != 0:
                log.error("Не удалось разбить большой файл, командой: " + command)
                return
            # archive original file
            archive_file = os.path.join(c['storage']['arc_out_path'], filename)
            if os.path.isfile(archive_file):
                log.warning("Разбитый файл с таким именем уже есть в архиве.")
            shutil.move(file_path_orig, archive_file)
            break

    # -- main work
    tmp_cache_size = 0
    with tempfile.TemporaryDirectory() as tmpdirpath:
        os.chdir(tmpdirpath)
        tmp_out = os.path.join(tmpdirpath, 'out')  # ready to be sent
        os.mkdir(tmp_out)

        success_file_names = set()
        # loop files/folders
        paths = sorted(Path(out_path).iterdir(), key=os.path.getmtime)
        for i, pure_path in enumerate(paths):  # oldest first
            filename = pure_path.name
            file_path_orig = str(pure_path)

            # skip hidden
            if filename == 'tmp' or filename == '.hidden' or filename == 'MOVED':
                continue
            # skip large folders
            siz = folder_size(file_path_orig) / 1000 / 1000  # M
            if siz > 500:  # skip big file > 500 MB
                continue
            orig_filename = filename  # required for zipped folders
            # Don't take fresh files
            if (time.time() - os.stat(file_path_orig).st_mtime) < 30:  # 30 sec
                log.info('Файлов {} был недавно изменен, обработаем позже'.format(filename))
                continue
            if os.path.isdir(file_path_orig):
                if (time.time() - os.stat(file_path_orig).st_mtime) < 60*10:
                    log.info('Директория {} была недавно изменена, обработаем позже'.format(filename))
                    continue
                for f_name in os.listdir(file_path_orig):
                    f_path = os.path.join(file_path_orig, f_name)
                    if (time.time() - os.stat(f_path).st_mtime) < 60*10:  # 10 m
                        log.info('Директория {} была недавно изменена, обработаем позже'.format(filename))
                        continue
                # returns file_path_orig + .zip
                file_path_orig = shutil.make_archive(filename, 'zip', file_path_orig)
                filename = filename + '.zip'
                # file_path_orig = zip in tmp or orig_file

            # rename and store in tmp
            t_file_p = os.path.join(tmpdirpath, str(i))
            shutil.copy(file_path_orig, t_file_p)

            # for recipient in c['enc_cert_thumbprint']:
            recipient = 'shluz'
            log.info('Подписываем и шифруем {}'.format(t_file_p))
            sf = sign_file(c['api']['sig_uri'], c['api']['sig_cert_thumbprint'],
                           c['api']['user'], c['api']['pass'], t_file_p, tmpdirpath)
            os.remove(t_file_p)
            if sf is None:
                exit(1)

            log.debug('Шифруем {}'.format(sf))
            ef = encrypt_file(c['api']['enc_uri'], c['enc_cert_thumbprint'][recipient],
                              c['api']['user'], c['api']['pass'], sf, tmpdirpath)
            os.remove(sf)
            if ef is None:
                exit(1)
            # rename file back to original + recipient + .sig.enc
            filename_orig_clear = '.'.join(filename.split('.')[:-1])  # without ending .xxx
            filename_ending = '.'.join(filename.split('.')[-1:])
            filename_final = filename_orig_clear + '.' + filename_ending + '.sig.enc'

            ef2 = os.path.join(tmp_out, filename_final)
            shutil.move(ef, ef2)
            ef = ef2
            log.debug('Поменяли имя на оригинальное {}'.format(ef))
            success_file_names.add(orig_filename)
            tmp_cache_size += os.stat(ef).st_size
            log.debug("tmp_cache_size " + str(tmp_cache_size) + " " + str(MAX_TMP_CACHE_SIZE))
            if tmp_cache_size > MAX_TMP_CACHE_SIZE:
                break

        if len(os.listdir(tmp_out)) != 0:
            # -- Send files
            command = 'echo -e put -r ' + tmp_out + '/*"\nquit\n" | sshpass -f ' + pass_path + ' ' + \
                      'sftp -oUser=rnb ftp.banksoyuz.ru:"' + target_remote_dir + '" > /dev/null'  # 2>&1
            log.debug(command)
            t = Timer(SSH_DELAY, timeout, ("SFTP Connection timeout",))
            t.start()
            res = os.system(command)  # "-i .ssh/openssh_key drop2.mkb.ru:rusnarbank/prod/in > /dev/null 2>&1")
            t.cancel()
            if res != 0:
                log.warning("Отправка файлов в СОЮЗ: Не получилось положить по sftp - проблема соединения.")
                return
            # -- Archive local
            archive_files = []
            for orig_file in success_file_names:
                source_f = os.path.join(out_path, orig_file)
                if '.7z.' in orig_file:
                    os.remove(source_f)
                else:
                    archive_file = os.path.join(c['storage']['arc_out_path'], orig_file)
                    if os.path.isfile(archive_file):
                        log.warning("Исходящий файл с таким именем уже есть в архиве.")
                    shutil.move(source_f, archive_file)
                    archive_files.append(archive_file)

            log.info('Отправили по SFTP: {}'.format(str(success_file_names)))
            if not email_is_special:  # daily
                inform_email(c, 'souz_inform', "Уведомление о файлах из РУСНАРБАНКА, ежедневных",
                             "В каталог {} отправлены файлы {}".format(target_remote_dir, str(success_file_names)))
                inform_email(c, 'out_copy', "Уведомление об отправке файла в СОЮЗ с копией",
                             "В каталог {} отправлены файлы {}".format(target_remote_dir, str(success_file_names)),
                             files=archive_files)
            else:  # special
                inform_email(c, 'souz_inform', "Уведомление о файлах из РУСНАРБАНКА отправленных вручную",
                             "В каталог {} отправлены файлы {}".format(target_remote_dir, str(success_file_names)))
                inform_email(c, 'out_special', "Уведомление о файлах из РУСНАРБАНКА отправленных вручную",
                             "В каталог {} отправлены файлы {}".format(target_remote_dir, str(success_file_names)))


def process_in(sftp_folder: str) -> None:
    """
    uses
    os.path.join(c['storage']['arc_in_path'] - local archive in
    c['storage']['in_path'] - local in
    c['storage']['in_special_path'] - local in_special

    pass_path - password file

    :param sftp_folder:
    :return:
    """
    log.info('Обрабатываю ВХОДЯЩИЕ')

    with tempfile.TemporaryDirectory() as tmpdirpath:
        os.chdir(tmpdirpath)
        # get all
        command = 'cd ' + tmpdirpath + ' ; ' +\
                  'echo -e get *"\nquit\n" | sshpass -f ' + pass_path + ' ' +\
                  'sftp -v -oUser=rnb ftp.banksoyuz.ru:"' + sftp_folder + '" > /dev/null 2>&1'
        log.debug(command)
        t = Timer(SSH_DELAY, timeout, ("SFTP Connection timeout",))
        t.start()
        res = os.system(command)  # "-i .ssh/openssh_key drop2.mkb.ru:rusnarbank/prod/in > /dev/null 2>&1")
        t.cancel()
        if res != 0:
            log.warning("Взятие файла в СОЮЗ: Не получилось взять по sftp - проблема соединения.")
            return

        log.debug("Получили файлы" + str(os.listdir(tmpdirpath)))

        success_files_daily = []
        success_files_special = []

        for i, filename_sftp in enumerate(os.listdir(tmpdirpath)):
            filename = filename_sftp
            # move wrong file name
            if re_in_file_wrong.fullmatch(filename_sftp.lower()) is not None:  # daily rus_01062021.csv.sig.enc (must be renamed)
                f_path_s = os.path.join(tmpdirpath, filename_sftp)
                filename = 'rnb' + filename_sftp[3:]
                f_path_t = os.path.join(tmpdirpath, filename)
                shutil.move(f_path_s, f_path_t)
            # set dest_path
            if re_in_file.fullmatch(filename.lower()) is not None:  # daily rnb_01062021.csv.sig.enc
                dest_path = c['storage']['in_path']
                email_is_daily = True
                if filename.lower() != in_file_start_name + (date.today() + timedelta(hours=7)).strftime("%d%m%Y") + '.csv.sig.enc':
                    log.warning("In file {} does match pattern but is not for today".format(filename.lower()))
            elif re_in_file_not_required.fullmatch(filename.lower()) is not None:  # daily rnb_01062021.xls.sig.enc
                res = remove_to_archive_sftp(filename_sftp, sftp_folder)
                if not res:
                    log.error("Не получилось удалить файл {} из SFTP {}".format(filename_sftp, sftp_folder))
                continue
            else:
                email_is_daily = False
                dest_path = c['storage']['in_special_path']

            # rename file to 0.sign.enc for comfortable request
            file_path_orig = os.path.join(tmpdirpath, filename)
            file_path = os.path.join(tmpdirpath, str(i) + '.sign.enc')
            shutil.move(file_path_orig, file_path)

            # file_path - new, filename_orig_clear - old
            log.debug("Обрабатываем входящий " + file_path)

            df = decrypt_file(c['api']['dec_uri'], c['api']['dec_cert_thumbprint'],
                              c['api']['user'], c['api']['pass'], file_path)
            if df is None:
                log.error('Ошибка ответа от сервиса расшифрования')
                continue

            log.debug("Начинаю UnSign входящий " + df)
            uns = None
            for who, key in c['enc_cert_thumbprint'].items():
                uns = unsign_file(c['api']['uns_uri'], c['enc_cert_thumbprint'][who],
                                  c['api']['user'], c['api']['pass'], df)
                if uns is not None:
                    log.debug("Извлекли подпись " + who)
                    break
            if uns is None:
                log.error('Ошибка ответа от сервиса извлечения подписи')
                continue
            log.debug("отделилили подпись " + uns)

            if uns is not None:
                filename_orig_clear_sftp = '.'.join(filename_sftp.split('.')[:-2])  # without sig.enc
                filename_orig_clear = '.'.join(filename.split('.')[:-2])  # without sig.enc
                # -- save in
                dest_pathfile = os.path.join(dest_path, filename_orig_clear)
                if os.path.isfile(dest_pathfile):  # file exist?
                    # archive exist file before replacing
                    log.warning("Входящий файл с таким именем уже существует. " + filename_orig_clear)
                    shutil.move(dest_pathfile, os.path.join(c['storage']['arc_in_path'], filename_orig_clear + str(round(time.time()))))
                # move to in
                shutil.move(uns, dest_pathfile)

                # -- REMOVE FROM SFTP ARCHIVE SFTP
                res = remove_to_archive_sftp(filename_sftp, sftp_folder)
                if not res:
                    log.error("Не получилось удалить файл {} из SFTP {}".format(filename_sftp, sftp_folder))
                    continue  # but we received file
                if email_is_daily:
                    success_files_daily.append(filename_orig_clear_sftp)
                else:
                    success_files_special.append(filename_orig_clear_sftp)
        if len(success_files_daily) != 0:
            log.info("Успешно получены ежедневные файлы: " + str(success_files_daily))
            inform_email(c, 'in_inform', "СОЮЗ-банк, получены ежедневные реестры",
                             "Получены файлы " + str(success_files_daily))
        elif len(success_files_special) != 0:
            log.info("Успешно получены особые файлы: " + str(success_files_special))
            inform_email(c, 'in_inform', "СОЮЗ-банк, получены файлы, SPECIAL!",
                         "Получены файлы " + str(success_files_special))


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
