# Makefile for the Cryppo project
# Created by Hongfei Yang (hongfei.yang@meeco.me) on 27 Dec 2020
# Cryppo requires OpenSSL 1.0.2 and above

# if you are using VS Code intellisense, remember to add /usr/local/opt/openssl/include to your include path
CC     = gcc
CFLAGS = -Wall -std=gnu99 -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
LL     = -lssl -lcrypto
EXE    = cryppo
OBJ    = cryppo.o


$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(LL)

cryppo.o: cryppo.c

# Run leaks detecting tool, provided by XCode
# If you are get 'could not load inserted library' error, run:
# cd /usr/local/lib
# sudo ln -s /Applications/Xcode.app/Contents/Developer/usr/lib/libLeaksAtExit.dylib
leaks:
	leaks -atExit -- ./$(EXE) | grep LEAK:

clean:
	rm -f $(OBJ) $(EXE)