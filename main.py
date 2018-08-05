#!/usr/bin/env python3
from configparser import ConfigParser
import socket

from re2oapi import Re2oAPIClient
from django.core.mail import send_mail
from django.template import loader, Context

from pprint import pprint

config = ConfigParser()
config.read('config.ini')

api_hostname = config.get('Re2o', 'hostname')
api_password = config.get('Re2o', 'password')
api_username = config.get('Re2o', 'username')

api_client = Re2oAPIClient(api_hostname,api_username,api_password)

client_hostname = socket.gethostname().split('.',1)[0]

def notif_end_adhesion(api_client):
    asso_options = api_client.list("preferences/assooption")
    from_mail = api_client.list("preferences/generaloption")["email_from"]
    template = loader.get_template('email_fin_adhesion')

    for result in api_client.list("reminder/get-users"):
        for user in result["users_to_remind"]:
            context = Context({
                'nom': user["get_full_name"],
                'temps': result["days"],
                'asso_name': asso_options["name"],
                'link': asso_options["site_url"]
                })
            print('mail envoyé à {}, reminder {} days'.format(user["get_full_name"],result["days"]))
            send_mail("Avis de fin d'adhésion / End of subscription notice",
                    '',
                    from_mail,
                    user["email"],
                    html_message = template.render(context)
            )

