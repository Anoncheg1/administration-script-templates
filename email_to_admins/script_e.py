#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
python3 script.py "Subject" "Message"
or echo "message" | python3 script.py "Subject"
"""

import sys
import logging
from os.path import basename
import os
import configparser as cp
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
import smtplib


def init_logger(level, logfile_path: str = None):
    """
    stderr  WARNING ERROR and CRITICAL
    stdout < WARNING

    :param logfile_path:
    :param level: level for stdout
    :return:
    """

    formatter = logging.Formatter('mkbsftp [%(asctime)s] %(levelname)-6s %(message)s')
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
    h1.addFilter(lambda record: record.levelno < logging.WARNING)
    h1.setFormatter(formatter)
    # stderr -- python3 script.py 2>&1 >/dev/null | xargs
    h2 = logging.StreamHandler(sys.stderr)
    h2.setLevel(logging.WARNING)  # fixed level
    h2.setFormatter(formatter)

    logger.addHandler(h1)
    logger.addHandler(h2)
    return logger


def config_load(path=u'./conf.conf'):
    try:
        config = cp.ConfigParser()
        config.read(path)
        params = dict()
        for section in config.sections():
            params[section] = {}
            for item in config.items(section):
                params[section][item[0]] = item[1]
        return params
    except cp.ParsingError:
        log.exception(u'Ошибка парсинга конфигурационного файла!')
        return None


def send_mail(username, password, send_from, send_to, subject,
              text, files=None, server="mx1.rnb.com"):
    assert isinstance(send_to, list)

    COMMASPACE = ', '

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(_text=text, _charset='UTF-8'))

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
    try:
        smtp.login(username, password)
        log.debug(u'Отправляю письмо на %s' % send_to)
        smtp.sendmail(send_from, send_to, msg.as_string())
    except Exception as e:
        log.exception("Fail to send email")
    finally:
        smtp.close()


def inform_email(c, send_to, subject, message):
    """
    :param subject:
    :param c: config dict
    :param send_to: list of strings
    :param message: string
    :return:
    """
    send_mail(c['inform_admins_imap']['login'], c['inform_admins_imap']['password'], c['inform_admins_imap']['address'],
              send_to=list(c[send_to].values()), text=message,
              subject=subject)


if __name__ == '__main__':

    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, 'script.conf')
    log_file = os.path.join(script_dir, 'email.log')
    c = config_load(config_file)  # GLOBAL
    log = init_logger(logging.DEBUG, log_file)  # GLOBAL
    # debug
    # inform_email(c, 'admins_addresses', "tst", "")

    if len(sys.argv) == 3:  # script "subject" and "message"
        inform_email(c, 'admins_addresses', sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 2:  # script and "subject"  - wait for message at stdin
        message = sys.stdin.readlines()
        if message is None or len(message) == 0:
            # no errors, ok
            exit(0)
        message = ''.join(message)
        subject = sys.argv[1]
        if "WARNING" in message:
            subject += " WARNING"
            inform_email(c, 'warn_admins_addresses', subject, message)
        else:
            inform_email(c, 'admins_addresses', subject, message)
    else:
        log.error("Wrong arguments " + str(sys.argv))


