SRC = pbp.c
OBJ = index.o script.o
LIBS = -lwebsockets -lev

all: pbp

pbp: pbp.c $(OBJ)
	$(CC) -o $@ $(LIBS) $(CFLAGS) $(LDFLAGS) $< $(OBJ)

index.o: index.html
	$(LD) $(LDFLAGS) -r -b binary -o $@ $<

script.o: script.js
	$(LD) $(LDFLAGS) -r -b binary -o $@ $<

clean:
	rm -f *.o pbp

.PHONY: clean
