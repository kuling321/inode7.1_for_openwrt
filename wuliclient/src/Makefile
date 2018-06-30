# build helloworld executable when user executes "make"

 PKG_NAME:=wuliclientBulidl

$(PKG_NAME): MD5.o wuliclient.o
	$(CC) $(LDFLAGS) MD5.o wuliclient.o -o $(PKG_NAME)

MD5.o: MD5.c
	$(CC) $(CFLAGS) -c MD5.c

wuliclient.o: wuliclient.c
	$(CC) $(CFLAGS) -c wuliclient.c

# remove object files and executable when user executes "make clean"
clean:
	rm *.o $(PKG_NAME)
