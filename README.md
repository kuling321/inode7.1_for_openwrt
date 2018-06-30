USED:

1.Download  the wuliclient directory to openwrt sdk packages directory.

[if you school H3C server ip is different from mine ,you should modify it.
 edit wuliclient.c and modify maroc of SER_ADRE SER_PORT and so on]

2.back to sdk top directory

3.running make

4.the .ipk in ./bin/[platform]/packages/base/

5.cp ipk to your route and install it.

6.running wuliclent with you "id passwd net_dev_id"
for example:
wuliclent 130105021035 1234 eth0

