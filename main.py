#!/usr/bin/env python3
from configparser import ConfigParser
import socket

from jinja2 import Environment, FileSystemLoader

from re2oapi import Re2oAPIClient, ApiSendMail

from pprint import pprint
import sys

config = ConfigParser()
config.read('config.ini')

api_hostname = config.get('Re2o', 'hostname')
api_password = config.get('Re2o', 'password')
api_username = config.get('Re2o', 'username')

api_client = Re2oAPIClient(api_hostname,api_username,api_password, use_tls=False)

api_mailserver = config.get('Mail', 'mailserver')
api_port = config.get('Mail', 'port')

api_sendmail = ApiSendMail(api_mailserver, api_port)

client_hostname = socket.gethostname().split('.',1)[0]

# Création de l'environnement Jinja
ENV = Environment(loader=FileSystemLoader('.'))

def notif_end_adhesion(api_client):
    asso_options = api_client.view("preferences/assooption/")
    general_options = api_client.view("preferences/generaloption/")
    template = ENV.get_template("templates/email_fin_adhesion")

    for result in api_client.list("reminder/get-users"):
        for user in result["users_to_remind"]:
            if "--verbose" in sys.argv:
                print('Mail envoyé à {}, reminder {} days'.format(user["get_full_name"],result["days"]))
            reminder_mail = template.render(
                nom=user["get_full_name"],
                temps=result["days"],
                asso_name=asso_options["name"],
                message=result["message"],
                link=general_options["main_site_url"])
            api_sendmail.send_mail(
                general_options["email_from"],
                user["get_mail"],
                "Avis de fin d'adhésion / End of subscription notice",
                reminder_mail
            )

## Manual command
if "--force" in sys.argv:
    notif_end_adhesion(api_client)

## Automatic regen
for service in api_client.list("services/regen/"):
    if service['hostname'] == client_hostname and \
        service['service_name'] == 'notif-users' and \
        service['need_regen']:
        notif_end_adhesion(api_client)
        api_client.patch(service['api_url'], data={'need_regen': False})
