CC     = gcc
CFLAGS = -Wall -std=gnu99 -lpthread -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
LL     = -lssl -lcrypto
EXE    = cryppo
OBJ    = cryppo.o


$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(LL)

cryppo.o: cryppo.c


clean:
	rm -f $(OBJ) $(EXE)