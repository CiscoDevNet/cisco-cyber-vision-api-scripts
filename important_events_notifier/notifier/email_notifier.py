#! /usr/bin/env python3
# encoding: utf-8

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class EmailNotifier:
    'Client Email Notifier'

    def __init__(self, host, port, login, password, use_tls = True, use_auth = True):
        self.host = host
        self.port = port
        self.use_auth = use_auth
        self.use_tls = use_tls
        self.login = login
        self.password = password

    def sendEmail(self, fromAddr, toAddr, subject, body):
        with smtplib.SMTP(self.host, self.port) as server:
            server.ehlo()
            if self.use_tls:
                server.starttls()
                server.ehlo()
            if self.use_auth:
                server.login(self.login, self.password)
            msg = MIMEMultipart()
            msg['From'] = fromAddr
            msg['To'] = toAddr
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            text = msg.as_string()
            server.sendmail(fromAddr, toAddr, text)
