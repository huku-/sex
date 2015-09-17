# Notes

Scraps of notes on **S.EX.** development.

huku &lt;[huku@grhack.net](mailto:huku@grhack.net)&gt;


## Purpose

As its name suggests, **S.EX.** is a shell script that extracts sections and
auxiliary information from various executable formats, namely, ELF, Mach-O and
PE-COFF (EXEs, DLLs, OCXs etc).

**S.EX.** was developed in order to be used as a first stage preprocessing tool
before an executable was analyzed by my disassembler named [xde](https://github.com/huku-/xde).
**S.EX.** would extract the required information using common command line tools
found in various Unixoids and **xde** would then load and disassemble any
executable sections using **sex_loader.py**. This was a simple and necessary
hack that was employed in order to avoid using several complex and incompatible
Python libraries for parsing executable file formats.

Nowadays I mostly use **S.EX.** for deeping into some executable file format
internals. My aim is to come up with a simple abstraction layer over the 3 most
famous executable formats mentioned before and then develop a Python library for
parsing them. This library, which is still being developed with a terribly slow
pace, will offer an abstract API for retrieving information from an executable
without the end programmer worrying about its actual format. Most people will
probably suggest **libbfd** as an alternative. However, apart from being a huge
C beast, **libbfd** has its own quirks and even bugs, that make it less than
ideal for my purpose.


## Coding style

**sex.sh** follows the
[Google shell style guide](http://google-styleguide.googlecode.com/svn/trunk/shell.xml).

