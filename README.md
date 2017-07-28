# Volatility-notpetyakeys
This Volatility plugin is used to search for AES key withing a memory snapshot of an infected host **on which NotPetya is running**.

### INSTALL
Put the `notpetya.py` file in the `volatility/plugins/malware/` directory.
Plugin should appear under `notpetyakeys` when running `vol.py --info`.


### Dependencies
This plugin depends on `yara`.


### Usage
```
vol.py -f mem --profile=<profile> notpetyakeys
```


### Output
Output is every AES key used by NotPetya (on per fixed drive).


### Next steps
Python decryption tool to come.


### Misc
(c) Wavestone 2017

Thanks to @gentilkiwi and @th3m4ks
