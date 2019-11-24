import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Tuple

import jinja2


class Mailer:
    def __init__(self, config: dict):
        self.host = config['host']
        self.ssl = config.get('ssl', False)
        self.starttls = config.get('starttls', False)
        self.keyfile = config.get('keyfile')
        self.certfile = config.get('certfile')
        assert not (self.ssl and self.starttls)
        if self.ssl:
            self.port = config.get('port', 465)
        elif self.starttls:
            self.port = config.get('port', 587)
        else:
            self.port = config.get('port', 25)
        self.user = config.get('user')
        self.password = config.get('password')
        self.sender = config['sender']
        self.site_base_url = config['siteBaseUrl']
        self.site_name = config['siteName']

    def connect(self) -> smtplib.SMTP:
        if self.ssl:
            keyfile = self.keyfile
            certfile = self.certfile
            context = ssl.create_default_context() if not keyfile and not certfile else None
            mailer = smtplib.SMTP_SSL(
                self.host, self.port, keyfile=keyfile, certfile=certfile, context=context
            )
        else:
            mailer = smtplib.SMTP(self.host, self.port)
        try:
            if self.starttls:
                keyfile = self.keyfile
                certfile = self.certfile
                context = ssl.create_default_context() if not keyfile and not certfile else None
                mailer.starttls(keyfile=keyfile, certfile=certfile, context=context)

            if self.user and self.password:
                mailer.login(self.user, self.password)
        except BaseException:
            mailer.close()
            raise
        return mailer

    def _render_template(self, language: str, name: str, **kwargs) -> Tuple[str, str]:
        if not os.path.isfile(os.path.join('mail', language, name)):
            language = 'en'

        with open(os.path.join('mail', language, name), 'r') as rf:
            template = jinja2.Template(rf.read())
        data = template.render(site_base_url=self.site_base_url, site_name=self.site_name, **kwargs)
        return data.split('\n', 1)

    def send_mail(self, language: str, name: str, to: str, context: dict):
        html_title, html_data = self._render_template(language, name + '.html.j2', **context)
        txt_title, txt_data = self._render_template(language, name + '.txt.j2', **context)
        assert txt_title == html_title

        message = MIMEMultipart('alternative')
        message['Subject'] = txt_title
        message.attach(MIMEText(html_data, 'html'))
        message.attach(MIMEText(txt_data, 'plain'))

        with self.connect() as mailer:
            mailer.sendmail(self.sender, [to], message.as_bytes())
