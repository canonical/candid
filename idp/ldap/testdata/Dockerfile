FROM docker.pkg.github.com/mhilton/openldap-docker/openldap
ENV DB_ROOT_PASSWORD={SSHA}7S4I62IxUGCX+t3ivcGVXQQAxH5deFxy
COPY *.pem /srv/ldap/certs/
COPY 00-config.ldif /srv/ldap/init/cn=config/
COPY 0rg.ldif group?.ldif user?.ldif /srv/ldap/init/dc=example,dc=com/
