# Volatility-notpetyakeys
This Volatility plugin is used to search for AES key withing a memory snapshot of an infected host **on which NotPetya is running**.

### INSTALL
Put the `notpetya.py` file in the `volatility/plugins/malware/` directory.
Plugin should appear under `notpetyakeys` when running `vol.py --info`.

### Input
The only input required is the 32-bit `rsaenh.dll` file from the filesystem of the infected host.
You will find it:
* On 32-bit hosts, at `C:\WINDOWS\System32\rsaenh.dll`
* On 64-bit hosts, at `C:\WINDOWS\SysWOW64\rsaenh.dll`

### Usage
```
vol.py -f mem --profile=<profile> notpetyakeys -r rsaenh.dll
```


### Output
Output is every AES key used by NotPetya (on per fixed drive).


### Next steps
Python decryption tool to come.


### Misc
(c) Wavestone 2017
Thanks to @gentilkiwi and @th3m4ks