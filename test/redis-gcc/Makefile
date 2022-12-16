REPO := https://github.com/redis/redis.git
VERSION := 5.0.2
DIR := redis-fp-st

all: clone patch build

clone:
	git clone --depth=1 --branch=$(VERSION) $(REPO) $(DIR)

patch:
	cd $(DIR); git apply ../stack-shuffle.PATCH

build:
	make -C $(DIR) noopt

clean:
	rm -rf $(DIR)
