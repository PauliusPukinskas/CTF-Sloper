rule flag_like { strings: $a="ctf_cs{" nocase $b="flag{" nocase $c="CTF{" nocase condition: any of them }
