FROM python:3.7-alpine

ADD requirements.txt /srv/
WORKDIR /srv

RUN apk --update add --virtual build-dependencies python3-dev build-base openldap-dev wget \
  && pip install -r requirements.txt \
  && pip install gunicorn \
  && apk del build-dependencies && rm -rf /var/cache/apk/*

ADD . /srv/

EXPOSE 80

CMD ["gunicorn", "-b", "0.0.0.0:80", "--timeout", "120", "--log-level", "debug", "server:app"]
