Use the Bitcoin network as an entropy source.

	$ python bitcoin-random-oracle.py HOST:PORT i-am-a-random-seed --pretty
	ad496d4b1a29d22cb6e5d76e70e43f9cd550feb3850596678f078bdb393dd811
	9d972721ca4adec07ec4ffaf059b35fcb5aacf9fd9b7aae99e4f8cf4be0b9539
	6d20cec73ebb2a1f4028729a157b40d6752f92c9663698fe548b04eec0b5b2ec
	65218be18bc681f2872ebeae6694805c9d357909adca31b4c4d32a5aedbbdd66
	05c31c91154f98e7255b9a3ab6ea63d46525d5dadbeebda093fad80e766ff9fe
	d1b0226dd68694f074fe612873441bd6e808ecdabb83a4906f4c1af0f9d615a2
	...

Or for basic usage instructions:

	python bitcoin-random-oracle.py

Here is an insane thing to do:

	mkfifo -m 0666 /tmp/insane-random-source
	python bitcoin-random-oracle.py HOST:PORT i-am-a-random-seed > /tmp/insane-random-source
	sudo rngd -r /tmp/insane-random-source

The strength of this as an entropy source is left as an exercise to the reader, but you probably shouldn't use this for anything real.

This is based on [halfnode](https://github.com/tcatm/halfnode).
