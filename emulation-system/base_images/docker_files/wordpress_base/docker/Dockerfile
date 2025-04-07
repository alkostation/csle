FROM kthnse/csle_flat_ubuntu_22_base:0.7.0
USER root

ENV DEBIAN_FRONTEND=noninteractive

### Mysql
# add our user and group first to make sure their IDs get assigned consistently, regardless of whatever dependencies get added
RUN groupadd -r mysql \
    && useradd -r -g mysql mysql \
    && apt-get update \
    && apt-get install -y --no-install-recommends gnupg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
# add gosu for easy step-down from root
# https://github.com/tianon/gosu/releases
ENV GOSU_VERSION 1.17
RUN set -eux; \
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends ca-certificates wget; \
	rm -rf /var/lib/apt/lists/*; \
	dpkgArch="$(dpkg --print-architecture | awk -F- '{ print $NF }')"; \
	wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch"; \
	wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-$dpkgArch.asc"; \
	export GNUPGHOME="$(mktemp -d)"; \
	gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
	gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu; \
	gpgconf --kill all; \
	rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc; \
	apt-mark auto '.*' > /dev/null; \
	[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark > /dev/null; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	chmod +x /usr/local/bin/gosu; \
	gosu --version; \
	gosu nobody true; \
  mkdir /docker-entrypoint-initdb.d

RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		bzip2 \
		openssl \
# FATAL ERROR: please install the following Perl modules before executing /usr/local/mysql/scripts/mysql_install_db:
# File::Basename
# File::Copy
# Sys::Hostname
# Data::Dumper
		perl \
		xz-utils \
		zstd \
	; \
	rm -rf /var/lib/apt/lists/*

RUN set -eux; \
# pub   rsa4096 2023-10-23 [SC] [expires: 2025-10-22]
#       BCA4 3417 C3B4 85DD 128E  C6D4 B7B3 B788 A8D3 785C
# uid           [ unknown] MySQL Release Engineering <mysql-build@oss.oracle.com>
# sub   rsa4096 2023-10-23 [E] [expires: 2025-10-22]
	key='BCA4 3417 C3B4 85DD 128E C6D4 B7B3 B788 A8D3 785C'; \
	export GNUPGHOME="$(mktemp -d)"; \
	gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "$key"; \
	mkdir -p /etc/apt/keyrings; \
	gpg --batch --export "$key" > /etc/apt/keyrings/mysql.gpg; \
	gpgconf --kill all; \
	rm -rf "$GNUPGHOME"

ENV MYSQL_MAJOR 8.0

#RUN echo 'deb [ signed-by=/etc/apt/keyrings/mysql.gpg ] http://repo.mysql.com/apt/debian/ bookworm mysql-8.0' > /etc/apt/sources.list.d/mysql.list

# the "/var/lib/mysql" stuff here is because the mysql-server postinst doesn't have an explicit way to disable the mysql_install_db codepath besides having a database already "configured" (ie, stuff in /var/lib/mysql/mysql)
# also, we set debconf keys to make APT a little quieter
RUN { \
		echo mysql-server mysql-server/data-dir select ''; \
		echo mysql-server mysql-server/root-pass password ''; \
		echo mysql-server mysql-server/re-root-pass password ''; \
		echo mysql-server mysql-server/remove-test-db select false; \
	} | debconf-set-selections \
	&& apt-get update \
	&& apt-get install -y \
		mysql-client-${MYSQL_MAJOR} \
		mysql-server-core-${MYSQL_MAJOR} \
	&& rm -rf /var/lib/apt/lists/* \
	&& rm -rf /var/lib/mysql && mkdir -p /var/lib/mysql /var/run/mysqld \
	&& chown -R mysql:mysql /var/lib/mysql /var/run/mysqld \
# ensure that /var/run/mysqld (used for socket and lock files) is writable regardless of the UID our mysqld instance ends up having at runtime
	&& chmod 1777 /var/run/mysqld /var/lib/mysql

#VOLUME /var/lib/mysql

# Config files
COPY ./docker_files/wordpress_base/docker/config/ /etc/mysql/

RUN chown -R mysql:mysql /var/lib/mysql \
    && rm -rf /var/lib/mysql/* \
    && su -s /bin/bash mysql -c "mysqld --initialize-insecure --user=mysql --datadir=/var/lib/mysql"




	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	

### PHP

RUN set -eux; \
	{ \
		echo 'Package: php*'; \
		echo 'Pin: release *'; \
		echo 'Pin-Priority: -1'; \
	} > /etc/apt/preferences.d/no-debian-php

# dependencies required for running "phpize"
# (see persistent deps below)
ENV PHPIZE_DEPS="autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c"

# persistent / runtime deps
RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		$PHPIZE_DEPS \
		ca-certificates \
		curl \
		xz-utils \
	; \
	rm -rf /var/lib/apt/lists/*

ENV PHP_INI_DIR /usr/local/etc/php
RUN set -eux; \
	mkdir -p "$PHP_INI_DIR/conf.d"; \
# allow running as an arbitrary user (https://github.com/docker-library/php/issues/743)
	[ ! -d /var/www/html ]; \
	mkdir -p /var/www/html; \
	chown www-data:www-data /var/www/html; \
	chmod 1777 /var/www/html

ENV APACHE_CONFDIR="/etc/apache2"
ENV APACHE_ENVVARS="$APACHE_CONFDIR/envvars"

RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends apache2; \
	rm -rf /var/lib/apt/lists/*; \
	\
# generically convert lines like
#   export APACHE_RUN_USER=www-data
# into
#   : ${APACHE_RUN_USER:=www-data}
#   export APACHE_RUN_USER
# so that they can be overridden at runtime ("-e APACHE_RUN_USER=...")
	sed -ri 's/^export ([^=]+)=(.*)$/: ${\1:=\2}\nexport \1/' "$APACHE_ENVVARS"; \
	\
# setup directories and permissions
	. "$APACHE_ENVVARS"; \
	for dir in \
		"$APACHE_LOCK_DIR" \
		"$APACHE_RUN_DIR" \
		"$APACHE_LOG_DIR" \
# https://salsa.debian.org/apache-team/apache2/-/commit/b97ca8714890ead1ba6c095699dde752e8433205
		"$APACHE_RUN_DIR/socks" \
	; do \
		rm -rvf "$dir"; \
		mkdir -p "$dir"; \
		chown "$APACHE_RUN_USER:$APACHE_RUN_GROUP" "$dir"; \
# allow running as an arbitrary user (https://github.com/docker-library/php/issues/743)
		chmod 1777 "$dir"; \
	done; \
	\
# delete the "index.html" that installing Apache drops in here
	rm -rvf /var/www/html/*; \
	\
# logs should go to stdout / stderr
	ln -sfT /dev/stderr "$APACHE_LOG_DIR/error.log"; \
	ln -sfT /dev/stdout "$APACHE_LOG_DIR/access.log"; \
	ln -sfT /dev/stdout "$APACHE_LOG_DIR/other_vhosts_access.log"; \
	chown -R --no-dereference "$APACHE_RUN_USER:$APACHE_RUN_GROUP" "$APACHE_LOG_DIR"

# Apache + PHP requires preforking Apache for best results
RUN a2dismod mpm_event \
    && a2enmod mpm_prefork

# PHP files should be handled by PHP, and should be preferred over any other file type
RUN { \
		echo '<FilesMatch \.php$>'; \
		echo '  SetHandler application/x-httpd-php'; \
		echo '</FilesMatch>'; \
		echo; \
		echo 'DirectoryIndex disabled'; \
		echo 'DirectoryIndex index.php index.html'; \
		echo; \
		echo '<Directory /var/www/html/wordpress>'; \
		echo '  Options -Indexes'; \
		echo '  AllowOverride All'; \
		echo '</Directory>'; \
	  } | tee "$APACHE_CONFDIR/conf-available/docker-php.conf" \
	  && a2enconf docker-php \
    && sed -i 's/^LogLevel warn/LogLevel debug/g' /etc/apache2/apache2.conf

# Apply stack smash protection to functions using local buffers and alloca()
# Make PHP's main executable position-independent (improves ASLR security mechanism, and has no performance impact on x86_64)
# Enable optimization (-O2)
# Enable linker optimization (this sorts the hash buckets to improve cache locality, and is non-default)
# https://github.com/docker-library/php/issues/272
# -D_LARGEFILE_SOURCE and -D_FILE_OFFSET_BITS=64 (https://www.php.net/manual/en/intro.filesystem.php)
ENV PHP_CFLAGS="-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64" \
    PHP_CPPFLAGS="$PHP_CFLAGS" \
    PHP_LDFLAGS="-Wl,-O1 -pie" \
    GPG_KEYS="1198C0117593497A5EC5C199286AF1F9897469DC C28D937575603EB4ABB725861C0779DC5C0A9DE4 AFD8691FDAEDF03BDF6E460563F15A9B715376CA" \
    PHP_VERSION="8.3.15" \
    PHP_URL="https://www.php.net/distributions/php-8.3.15.tar.xz" \
    PHP_ASC_URL="https://www.php.net/distributions/php-8.3.15.tar.xz.asc" \
    PHP_SHA256="3df5d45637283f759eef8fc3ce03de829ded3e200c3da278936a684955d2f94f"

RUN set -eux; \
	\
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends gnupg; \
	rm -rf /var/lib/apt/lists/*; \
	\
	mkdir -p /usr/src; \
	cd /usr/src; \
	\
	curl -fsSL -o php.tar.xz "$PHP_URL"; \
	\
	if [ -n "$PHP_SHA256" ]; then \
		echo "$PHP_SHA256 *php.tar.xz" | sha256sum -c -; \
	fi; \
	\
	if [ -n "$PHP_ASC_URL" ]; then \
		curl -fsSL -o php.tar.xz.asc "$PHP_ASC_URL"; \
		export GNUPGHOME="$(mktemp -d)"; \
		for key in $GPG_KEYS; do \
			gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "$key"; \
		done; \
		gpg --batch --verify php.tar.xz.asc php.tar.xz; \
		gpgconf --kill all; \
		rm -rf "$GNUPGHOME"; \
	fi; \
	\
	apt-mark auto '.*' > /dev/null; \
	apt-mark manual $savedAptMark > /dev/null; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false

COPY ./docker_files/wordpress_base/docker/docker-php-source /usr/local/bin/

RUN set -eux; \
	\
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		apache2-dev \
		libargon2-dev \
		libcurl4-openssl-dev \
		libonig-dev \
		libreadline-dev \
		libsodium-dev \
		libsqlite3-dev \
		libssl-dev \
		libxml2-dev \
		zlib1g-dev \
	; \
	\
	export \
		CFLAGS="$PHP_CFLAGS" \
		CPPFLAGS="$PHP_CPPFLAGS" \
		LDFLAGS="$PHP_LDFLAGS" \
# https://github.com/php/php-src/blob/d6299206dd828382753453befd1b915491b741c6/configure.ac#L1496-L1511
		PHP_BUILD_PROVIDER='https://github.com/docker-library/php' \
		PHP_UNAME='Linux - Docker' \
	; \
	docker-php-source extract; \
	cd /usr/src/php; \
	gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; \
	debMultiarch="$(dpkg-architecture --query DEB_BUILD_MULTIARCH)"; \
# https://bugs.php.net/bug.php?id=74125
	if [ ! -d /usr/include/curl ]; then \
		ln -sT "/usr/include/$debMultiarch/curl" /usr/local/include/curl; \
	fi; \
	./configure \
		--build="$gnuArch" \
		--with-config-file-path="$PHP_INI_DIR" \
		--with-config-file-scan-dir="$PHP_INI_DIR/conf.d" \
		\
# make sure invalid --configure-flags are fatal errors instead of just warnings
		--enable-option-checking=fatal \
		\
# https://github.com/docker-library/php/issues/439
		--with-mhash \
		\
# https://github.com/docker-library/php/issues/822
		--with-pic \
		\
# --enable-mbstring is included here because otherwise there's no way to get pecl to use it properly (see https://github.com/docker-library/php/issues/195)
		--enable-mbstring \
# --enable-mysqlnd is included here because it's harder to compile after the fact than extensions are (since it's a plugin for several extensions, not an extension in itself)
		--enable-mysqlnd \
# https://wiki.php.net/rfc/argon2_password_hash
		--with-password-argon2 \
# https://wiki.php.net/rfc/libsodium
		--with-sodium=shared \
# always build against system sqlite3 (https://github.com/php/php-src/commit/6083a387a81dbbd66d6316a3a12a63f06d5f7109)
		--with-pdo-sqlite=/usr \
		--with-sqlite3=/usr \
		\
		--with-curl \
		--with-iconv \
		--with-openssl \
		--with-readline \
		--with-zlib \
		\
# https://github.com/bwoebi/phpdbg-docs/issues/1#issuecomment-163872806 ("phpdbg is primarily a CLI debugger, and is not suitable for debugging an fpm stack.")
		--disable-phpdbg \
		\
# in PHP 7.4+, the pecl/pear installers are officially deprecated (requiring an explicit "--with-pear")
		--with-pear \
		\
		--with-libdir="lib/$debMultiarch" \
		\
		--disable-cgi \
		\
		--with-apxs2 \
	; \
	make -j "$(nproc)"; \
	find -type f -name '*.a' -delete; \
	make install; \
	find \
		/usr/local \
		-type f \
		-perm '/0111' \
		-exec sh -euxc ' \
			strip --strip-all "$@" || : \
		' -- '{}' + \
	; \
	make clean; \
	\
# https://github.com/docker-library/php/issues/692 (copy default example "php.ini" files somewhere easily discoverable)
	cp -v php.ini-* "$PHP_INI_DIR/"; \
	\
	cd /; \
	docker-php-source delete; \
	\
# reset apt-mark's "manual" list so that "purge --auto-remove" will remove all build dependencies
	apt-mark auto '.*' > /dev/null; \
	[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark; \
	find /usr/local -type f -executable -exec ldd '{}' ';' \
		| awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\n", so }' \
		| sort -u \
		| xargs -r dpkg-query --search \
		| cut -d: -f1 \
		| sort -u \
		| xargs -r apt-mark manual \
	; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	rm -rf /var/lib/apt/lists/*; \
	\
# update pecl channel definitions https://github.com/docker-library/php/issues/443
	pecl update-channels; \
	rm -rf /tmp/pear ~/.pearrc; \
  \
# smoke test
	php --version

COPY ./docker_files/wordpress_base/docker/docker-php-ext*  /usr/local/bin/

# sodium was built as a shared module (so that it can be replaced later if so desired), so let's enable it too (https://github.com/docker-library/php/issues/598)
RUN docker-php-ext-enable sodium

















### Wordpress
# persistent dependencies
RUN set -eux; \
apt-get update; \
apt-get install -y --no-install-recommends \
# Ghostscript is required for rendering PDF previews
  ghostscript less sendmail pip \
; \
rm -rf /var/lib/apt/lists/*

# install the PHP extensions we need (https://make.wordpress.org/hosting/handbook/handbook/server-environment/#php-extensions)
RUN set -ex; \
\
savedAptMark="$(apt-mark showmanual)"; \
\
apt-get update; \
apt-get install -y --no-install-recommends \
  libavif-dev \
  libfreetype6-dev \
  libicu-dev \
  libjpeg-dev \
  libmagickwand-dev \
  libpng-dev \
  libwebp-dev \
  libzip-dev \
; \
\
docker-php-ext-configure gd \
  --with-avif \
  --with-freetype \
  --with-jpeg \
  --with-webp \
; \
docker-php-ext-install -j "$(nproc)" \
  bcmath \
  exif \
  gd \
  intl \
  mysqli \
  zip \
; \
# https://pecl.php.net/package/imagick
# https://github.com/Imagick/imagick/commit/5ae2ecf20a1157073bad0170106ad0cf74e01cb6 (causes a lot of build failures, but strangely only intermittent ones 🤔)
# see also https://github.com/Imagick/imagick/pull/641
# this is "pecl install imagick-3.7.0", but by hand so we can apply a small hack / part of the above commit
curl -fL -o imagick.tgz 'https://pecl.php.net/get/imagick-3.7.0.tgz'; \
echo '5a364354109029d224bcbb2e82e15b248be9b641227f45e63425c06531792d3e *imagick.tgz' | sha256sum -c -; \
tar --extract --directory /tmp --file imagick.tgz imagick-3.7.0; \
grep '^//#endif$' /tmp/imagick-3.7.0/Imagick.stub.php; \
test "$(grep -c '^//#endif$' /tmp/imagick-3.7.0/Imagick.stub.php)" = '1'; \
sed -i -e 's!^//#endif$!#endif!' /tmp/imagick-3.7.0/Imagick.stub.php; \
grep '^//#endif$' /tmp/imagick-3.7.0/Imagick.stub.php && exit 1 || :; \
docker-php-ext-install /tmp/imagick-3.7.0; \
rm -rf imagick.tgz /tmp/imagick-3.7.0; \
\
# some misbehaving extensions end up outputting to stdout 🙈 (https://github.com/docker-library/wordpress/issues/669#issuecomment-993945967)
out="$(php -r 'exit(0);')"; \
[ -z "$out" ]; \
err="$(php -r 'exit(0);' 3>&1 1>&2 2>&3)"; \
[ -z "$err" ]; \
\
extDir="$(php -r 'echo ini_get("extension_dir");')"; \
[ -d "$extDir" ]; \
# reset apt-mark's "manual" list so that "purge --auto-remove" will remove all build dependencies
apt-mark auto '.*' > /dev/null; \
apt-mark manual $savedAptMark; \
ldd "$extDir"/*.so \
  | awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\n", so }' \
  | sort -u \
  | xargs -r dpkg-query --search \
  | cut -d: -f1 \
  | sort -u \
  | xargs -rt apt-mark manual; \
\
apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
rm -rf /var/lib/apt/lists/*; \
\
! { ldd "$extDir"/*.so | grep 'not found'; }; \
# check for output like "PHP Warning:  PHP Startup: Unable to load dynamic library 'foo' (tried: ...)
err="$(php --version 3>&1 1>&2 2>&3)"; \
[ -z "$err" ]

# set recommended PHP.ini settings
# see https://secure.php.net/manual/en/opcache.installation.php
RUN set -eux; \
docker-php-ext-enable opcache; \
{ \
  echo 'opcache.memory_consumption=128'; \
  echo 'opcache.interned_strings_buffer=8'; \
  echo 'opcache.max_accelerated_files=4000'; \
  echo 'opcache.revalidate_freq=2'; \
} > /usr/local/etc/php/conf.d/opcache-recommended.ini
# https://wordpress.org/support/article/editing-wp-config-php/#configure-error-logging
RUN { \
# https://www.php.net/manual/en/errorfunc.constants.php
# https://github.com/docker-library/wordpress/issues/420#issuecomment-517839670
  echo 'error_reporting = E_ERROR | E_WARNING | E_PARSE | E_CORE_ERROR | E_CORE_WARNING | E_COMPILE_ERROR | E_COMPILE_WARNING | E_RECOVERABLE_ERROR'; \
  echo 'display_errors = Off'; \
  echo 'display_startup_errors = Off'; \
  echo 'log_errors = On'; \
  echo 'error_log = /dev/stderr'; \
  echo 'log_errors_max_len = 1024'; \
  echo 'ignore_repeated_errors = On'; \
  echo 'ignore_repeated_source = Off'; \
  echo 'html_errors = Off'; \
} > /usr/local/etc/php/conf.d/error-logging.ini

RUN set -eux; \
a2enmod rewrite expires; \
\
# https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html
a2enmod remoteip; \
{ \
  echo 'RemoteIPHeader X-Forwarded-For'; \
# these IP ranges are reserved for "private" use and should thus *usually* be safe inside Docker
  echo 'RemoteIPInternalProxy 10.0.0.0/8'; \
  echo 'RemoteIPInternalProxy 172.16.0.0/12'; \
  echo 'RemoteIPInternalProxy 192.168.0.0/16'; \
  echo 'RemoteIPInternalProxy 169.254.0.0/16'; \
  echo 'RemoteIPInternalProxy 127.0.0.0/8'; \
} > /etc/apache2/conf-available/remoteip.conf; \
a2enconf remoteip; \
# https://github.com/docker-library/wordpress/issues/383#issuecomment-507886512
# (replace all instances of "%h" with "%a" in LogFormat)
find /etc/apache2 -type f -name '*.conf' -exec sed -ri 's/([[:space:]]*LogFormat[[:space:]]+"[^"]*)%h([^"]*")/\1%a\2/g' '{}' +

RUN set -eux; \
version='6.7.1'; \
sha1='dfb745d4067368bb9a9491f2b6f7e8d52d740fd1'; \
\
curl -o wordpress.tar.gz -fL "https://wordpress.org/wordpress-$version.tar.gz"; \
echo "$sha1 *wordpress.tar.gz" | sha1sum -c -; \
\
# upstream tarballs include ./wordpress/ so this gives us /usr/src/wordpress
tar -xzf wordpress.tar.gz -C /var/www/html/; \
rm wordpress.tar.gz; \
\
# https://wordpress.org/support/article/htaccess/
[ ! -e /var/www/html/.htaccess ]; \
{ \
  echo '# BEGIN WordPress'; \
  echo ''; \
  echo 'RewriteEngine On'; \
  echo 'RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]'; \
  echo 'RewriteBase /'; \
  echo 'RewriteRule ^index\.php$ - [L]'; \
  echo 'RewriteCond %{REQUEST_FILENAME} !-f'; \
  echo 'RewriteCond %{REQUEST_FILENAME} !-d'; \
  echo 'RewriteRule . /index.php [L]'; \
  echo ''; \
  echo '# END WordPress'; \
} > /var/www/html/wordpress/.htaccess; \
\
chown -R www-data:www-data /var/www/html/wordpress; \
# pre-create wp-content (and single-level children) for folks who want to bind-mount themes, etc so permissions are pre-created properly instead of root:root
# wp-content/cache: https://github.com/docker-library/wordpress/issues/534#issuecomment-705733507
mkdir wp-content; \
for dir in /var/www/html/wordpress/wp-content/*/ cache; do \
  dir="$(basename "${dir%/}")"; \
  mkdir "wp-content/$dir"; \
done; \
chown -R www-data:www-data wp-content; \
chmod -R 1777 wp-content; \
sed -i 's|DocumentRoot /var/www/html$|DocumentRoot /var/www/html/wordpress|' /etc/apache2/sites-enabled/000-default.conf

#VOLUME /var/www/html

#COPY --chown=www-data:www-data ./docker_files/wordpress_base/docker/wp-config-docker.php /var/www/html/wordpress/

ENV WORDPRESS_DB_NAME=wordpress \
    WORDPRESS_DB_USER=wordpress \
    WORDPRESS_DB_PASSWORD=wordpress \
    WORDPRESS_DB_HOST="127.0.0.1" \
    WORDPRESS_DB_CHARSET=utf8 \
    WORDPRESS_DB_COLLATE=utf8_general_ci \
    WORDPRESS_TABLE_PREFIX=wp_ \
    WORDPRESS_DEBUG=1 \
    WORDPRESS_CONFIG_EXTRA="" \
    WORDPRESS_AUTH_KEY="$(openssl rand -base64 32)" \
    WORDPRESS_SECURE_AUTH_KEY="$(openssl rand -base64 32)" \
    WORDPRESS_LOGGED_IN_KEY="$(openssl rand -base64 32)" \
    WORDPRESS_NONCE_KEY="$(openssl rand -base64 32)" \
    WORDPRESS_AUTH_SALT="$(openssl rand -base64 32)" \
    WORDPRESS_SECURE_AUTH_SALT="$(openssl rand -base64 32)" \
    WORDPRESS_LOGGED_IN_SALT="$(openssl rand -base64 32)" \
    WORDPRESS_NONCE_SALT="$(openssl rand -base64 32)" \
    WORDPRESS_URL="http://localhost" \
    WORDPRESS_TITLE="AInception-SL700-WEB-site" \
    WORDPRESS_ADMIN_USER=admin \
    WORDPRESS_ADMIN_PASSWORD=admin \
    WORDPRESS_ADMIN_EMAIL=test@sl700.com

ADD ./docker_files/wordpress_base/docker/wpdiscuz-7.0.4.tar.gz /var/www/html/wordpress/wp-content/plugins/

RUN set -eux \
    && su -s /bin/bash mysql -c "mysqld --user=mysql -D" \
    && mysql -u root -e "CREATE DATABASE IF NOT EXISTS $WORDPRESS_DB_NAME;" \
    && mysql -u root -e "CREATE USER IF NOT EXISTS '$WORDPRESS_DB_USER'@'%' IDENTIFIED BY '$WORDPRESS_DB_PASSWORD';" \
    && mysql -u root -e "GRANT ALL PRIVILEGES ON $WORDPRESS_DB_NAME.* TO '$WORDPRESS_DB_USER'@'%';" \
    && mysql -u root -e "FLUSH PRIVILEGES;" \
    && curl -o /usr/local/bin/wp-cli.phar https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    && pip install requests bs4

# Setup root SSH
RUN mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
ADD docker_files/common/sshd_config /etc/ssh/sshd_config

ADD ./docker_files/wordpress_base/docker/script.sh /script.sh
RUN chmod 777 /script.sh

EXPOSE 22/tcp 80/tcp

COPY ./docker_files/wordpress_base/docker/docker-entrypoint.sh ./docker_files/wordpress_base/docker/wpDiscuz-activate.py /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
#CMD ["apache2-foreground"]
#WORKDIR /var/www/html
