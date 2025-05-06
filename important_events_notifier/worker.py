#!/usr/bin/env python3
# encoding: utf-8

# NOTE: If you are using https protocol, you need to set environment
# variable 'REQUESTS_CA_BUNDLE' to your CA certificate file, available
# at 'http://YOUR_CENTER_IP/ca.pem'
#
# Exemple: REQUESTS_CA_BUNDLE=~/ca.pem python yourscript.py

import json
import os
from pathlib import Path
from datetime import date, timedelta
from configparser import ConfigParser
from sys import exit

from api import cybervision
from renderer import text, short_text
from notifier import email_notifier

class Config():
    def load(self, filename="config.ini"):
        filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)),filename)
        p = Path(filepath)
        if p.is_file:
            config = ConfigParser()
            config.read(str(p))

            # get env vars
            self.host        = config.get('Common', 'host')
            self.token       = config.get('Common', 'token')
            self.dbPath      = config.get('Common', 'db_path')
            self.limit       = config.getint('Common', 'limit')
            self.clientCertFilePath = config.get('Common', 'client_cert_filepath')
            self.clientPrivKeyFilePath = config.get('Common', 'client_privkey_filepath')

            # email notifier
            self.useEmailNotifier = config.getboolean( 'Email', 'use_email_notifier')
            self.fromAddr = config.get( 'Email', 'from')
            self.toAddr = config.get( 'Email', 'to')
            self.smptHost = config.get( 'Email', 'host')
            self.smptPort = config.get( 'Email', 'port')
            self.smptLogin = config.get( 'Email', 'login')
            self.smptPassword = config.get( 'Email', 'password')
            self.useTLS = config.getboolean( 'Email', 'use_tls')
            self.useSmtpAuth = config.getboolean( 'Email', 'use_auth')

            # filters
            print(config.get( 'Filters', 'filter_severities'))
            self.filter_severities = json.loads(config.get( 'Filters', 'filter_severities'))
            self.filter_categories = json.loads(config.get( 'Filters', 'filter_categories'))

        else:
            print(('Error: Configuration file %s not found' % p.name))
            exit(1)

def run():
    # Init filters
    today               = date.today()
    filter_start        = today - timedelta(days=1)
    filter_end          = today + timedelta(days=1)

    #Get configuration
    config = Config()
    config.load()

    # Init notifiers
    if config.useEmailNotifier:
        emailNotifier = email_notifier.EmailNotifier(config.smptHost, config.smptPort, config.smptLogin, config.smptPassword, \
             config.useTLS, config.useSmtpAuth)

    # Retrieve all events from interval
    events = []

    route = "/api/1.0/event"
    parameters = {
        'start': filter_start.strftime('%Y-%m-%d %H:%M'),
        'end': filter_end.strftime('%Y-%m-%d %H:%M'),
        'severity': config.filter_severities,
        'category': config.filter_categories,
    }
    #tmp = cybervision.get_last_events(config.token, config.host, filter_severities, mins=1000)
    data = cybervision.call_route_recursive(route, config.token, config.host, debug=True, params=parameters, max_element=config.limit)
    #data = json.loads(jsdata)
    for event in data:
        events.append(event)

    newEvents = []
    # Check if event ID already exists in DB
    # We persist DB in case of the daemon crash and restart to avoid another alert for an event already proceded
    dbPath = Path(os.path.join(os.path.dirname(os.path.abspath(__file__)),config.dbPath))
    if dbPath.is_file():
        with open(str(dbPath), 'r') as db:
            lines = db.readlines()
            oldEvents = set()
            for line in lines:
                oldEvents.add(line.strip())
            for event in events:
                if event["id"] not in oldEvents:
                    newEvents.append(event)
    else:
        for event in events:
            newEvents.append(event)

    nbNewEvents = len(newEvents)
    if nbNewEvents > 0:
        print(("%d new important event(s) from %s to %s." % (nbNewEvents, filter_start, filter_end)))

        # Send notifications (Email + SMS)
        if config.useEmailNotifier is True:
            emailBody = text.render(newEvents, "https://%s" % config.host)
            subject = "Cisco Cyber Vision - %d Important Event(s) (From: %s To: %s)" % (nbNewEvents, filter_start, filter_end)
            emailNotifier.sendEmail(config.fromAddr, config.toAddr, subject, emailBody)
            print("Email sending successfully with subject : \"%s\"" % subject)
        else:
            print("Warning: Email notification is disabled, skip sending.")

        # Do persit to avoid to resend notification
        with open(str(dbPath), 'a') as db:
            for newEvent in newEvents:
                db.write("%s\n" % newEvent["id"])
        print("The event IDs are persisted to avoid to resend notification (see: %s)." % (config.dbPath))
    else:
        print("No new events yet, do not send notification.")

    newEvents = [] # Reset


if __name__=="__main__":
    run()
