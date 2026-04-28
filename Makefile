all: bchoc

bchoc: bchoc.py
	cp bchoc.py bchoc
	chmod +x bchoc

clean:
	rm -f bchoc