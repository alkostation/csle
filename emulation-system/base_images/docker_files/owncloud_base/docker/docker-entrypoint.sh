#!/bin/bash

set -e

while [ -z  "$(ip a show eth0 | grep 'inet ')" ]; do
    echo "Waiting for eth0 to be available..."
    sleep 2
done

echo "Starting SSH daemon..."
/usr/sbin/sshd -D &

apache2ctl start

mariadbd --user=mysql &

redis-server /etc/redis/redis.conf

sleep 5

mysql -u root -e \
  "CREATE DATABASE IF NOT EXISTS owncloud; \
  CREATE USER IF NOT EXISTS 'owncloud'@'localhost' IDENTIFIED BY 'password'; \
  GRANT ALL PRIVILEGES ON *.* TO 'owncloud'@'localhost' WITH GRANT OPTION; \
  FLUSH PRIVILEGES;"

sleep 2

occ maintenance:install \
    --database "mysql" \
    --database-name "owncloud" \
    --database-user "owncloud" \
    --database-pass "password" \
    --data-dir "/var/www/owncloud/data" \
    --admin-user "admin" \
    --admin-pass "admin"

my_ip=$(hostname -I|cut -f1 -d ' ')

occ config:system:set trusted_domains 1 --value="$my_ip"

occ background:cron

echo "*/15  *  *  *  * /var/www/owncloud/occ system:cron" \
  | sudo -u www-data -g crontab tee -a \
  /var/spool/cron/crontabs/www-data
echo "0  2  *  *  * /var/www/owncloud/occ dav:cleanup-chunks" \
  | sudo -u www-data -g crontab tee -a \
  /var/spool/cron/crontabs/www-data

occ config:system:set \
   memcache.local \
   --value '\OC\Memcache\APCu'
occ config:system:set \
   memcache.locking \
   --value '\OC\Memcache\Redis'
occ config:system:set \
   redis \
   --value '{"host": "127.0.0.1", "port": "6379"}' \
   --type json

occ -V

while true; do
    sleep 10;
done
