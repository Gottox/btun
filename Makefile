SRC = btun.c
OBJ = index.o script.o
LIBS = -lwebsockets -lev

all: btun

btun: $(SRC) $(OBJ)
	$(CC) -o $@ $(LIBS) $(CFLAGS) $(LDFLAGS) $(SRC) $(OBJ)

index.o: index.html
	$(LD) $(LDFLAGS) -r -b binary -o $@ $<

script.o: script.js
	$(LD) $(LDFLAGS) -r -b binary -o $@ $<

clean:
	rm -f *.o btun

.PHONY: clean
