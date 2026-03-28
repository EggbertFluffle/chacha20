main: chacha20 salsaX

chacha20: chacha20.c
	gcc chacha20.c -o chacha20 -g

salsaX: salsaX.c
	gcc salsaX.c -o salsax-g
