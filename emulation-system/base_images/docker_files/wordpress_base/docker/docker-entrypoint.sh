#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Generate host keys if they don't exist
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    echo "Generating SSH host keys..."
    ssh-keygen -A
fi

# Ensure proper ownership of the SSH directory
chown -R root:root /etc/ssh

# Start the SSH daemon
echo "Starting SSH daemon..."
/usr/sbin/sshd -f /etc/ssh/sshd_config -D &

IP=$(ip a s dev eth0 | grep inet | awk '{print $2}' | sed 's/\/.\+//g')
apache2ctl start
su -s /bin/bash mysql -c "mysqld --user=mysql -D"

su -s /bin/bash www-data \
   -c "php /usr/local/bin/wp-cli.phar config create \
      --dbname=$WORDPRESS_DB_NAME  \
      --dbuser=$WORDPRESS_DB_USER  \
      --dbpass=$WORDPRESS_DB_PASSWORD \
      --dbhost=$WORDPRESS_DB_HOST  \
      --dbcharset=$WORDPRESS_DB_CHARSET  \
      --dbcollate=$WORDPRESS_DB_COLLATE  \
      --path=/var/www/html/wordpress"

su -s /bin/bash www-data \
   -c "php /usr/local/bin/wp-cli.phar core install \
      --url=http://$IP \
      --title=$WORDPRESS_TITLE \
      --admin_user=$WORDPRESS_ADMIN_USER \
      --admin_password=$WORDPRESS_ADMIN_PASSWORD \
      --admin_email=$WORDPRESS_ADMIN_EMAIL \
      --path=/var/www/html/wordpress \
      --skip-email"

# Activate wpDiscuz plugin
python3 /usr/local/bin/wpDiscuz-activate.py \
   http://$IP \
   $WORDPRESS_ADMIN_USER \
   $WORDPRESS_ADMIN_PASSWORD

while true; do sleep 100; done
