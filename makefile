SOURCE = sniffer.c
TARGET = sniffre
all: $(SOURCE)
	gcc -o $(TARGET) $(SOURCE) -lpcap -lpcre
clean:
	$(RM) $(TARGET)
