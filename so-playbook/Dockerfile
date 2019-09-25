
FROM redmine:4-passenger
#FROM redmine:4-alpine

MAINTAINER Josh Brower <josh@defensivedepth.com>

WORKDIR /usr/src/redmine

ADD playbook/plugin/redmine_playbook.tar.bz2   /usr/src/redmine/plugins

ADD playbook/circle_theme.tar.bz2   /usr/src/redmine/public/themes

COPY playbook/redmine.db /usr/src/redmine/sqlite/redmine.db

RUN chown redmine:redmine /usr/src/redmine/sqlite/redmine.db

RUN git clone https://github.com/suer/redmine_webhook.git /usr/src/redmine/plugins/redmine_webhook

COPY playbook/passenger-nginx-config-template.erb /passenger-nginx-config-template.erb

CMD ["passenger", "start", "--nginx-config-template", "/passenger-nginx-config-template.erb"]
