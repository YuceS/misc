CFLAGS  += -O2 -Wall -Wextra
LDFLAGS += -lpcap
OBJS     = intercept.o
BIN      = intercept
.PHONY   = all clean install

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) -o $(BIN) $(OBJS) $(LDFLAGS)

install: $(BIN)
	sudo install -o root -g root -m 0755 -s -D intercept /usr/local/sbin/intercept
	sudo install -o root -g root -m 0644 -D intercept.service /etc/systemd/system/intercept.service
	sudo systemctl daemon-reload
	@echo "If your network interfaces are not named eth0 and eth1, then edit"
	@echo "/etc/systemd/system/intercept.service and issue: sudo systemctl daemon-reload"
	@echo "To start the service at boot, run: sudo systemctl enable intercept"
	@echo "To start the service now, run: sudo systemctl start intercept"

clean:
	rm -f $(BIN) $(OBJS)
