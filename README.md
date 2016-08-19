# S.EX. a.k.a. Section EXtractor

huku &lt;[huku@grhack.net](mailto:huku@grhack.net)&gt;


## About

This is a small shell script I developed for personal use. It exports sections
and auxiliary information from various executable file formats (ELF, PE-COFF,
FAT & Mach-O). Exported sections are dumped in files whose names match the
pattern shown below:

```
$name-$vma-$size-$offset-$flags.bin
```

**$name** - Section name

**$vma** - Virtual memory address where the section is loaded at runtime

**$size** - Size of section in bytes

**$offset** - Offset of section data in the executable

**$flags** - Letters indicating if the section is loaded (**l**), readable
(**r**), writable (**w**) or executable (**x**)

A file named **aux.ini** contains information about an executable's entry
points, exit points, relocations and function boundaries. **aux.ini** can be
parsed using Python's [ConfigParser](https://docs.python.org/2/library/configparser.html).


## Installing S.EX.

To install S.EX. just issue the following command:

```sh
$ sudo python setup.py install
```

The setup script will install a Python module named **sex** under **site-packages**
and a shell script named **sex**, usually, under **/usr/local/bin**.


## Using S.EX.

Here's how **sex** looks like when ran on a MacOS X system against Microsoft
Windows' **calc.exe**.

```sh
$ sex calc.exe
(2015-09-17 12:44:57) [*] Creating directory "calc.exe.sex"
(2015-09-17 12:44:57) [*] Storing auxiliary information in "calc.exe.sex/aux.ini"
(2015-09-17 12:44:57) [*] bins/calc.exe: PE-COFF
(2015-09-17 12:44:57) [*] Dumping section ".text" in "calc.exe.sex/.text-0x0000000100001000-396489-1536-lr_x.bin"
(2015-09-17 12:44:58) [*] Dumping section ".rdata" in "calc.exe.sex/.rdata-0x0000000100062000-69316-398336-lrw_.bin"
(2015-09-17 12:44:58) [*] Dumping section ".data" in "calc.exe.sex/.data-0x0000000100073000-19968-467968-lrw_.bin"
(2015-09-17 12:44:58) [*] Dumping section ".pdata" in "calc.exe.sex/.pdata-0x0000000100078000-25764-487936-lrw_.bin"
(2015-09-17 12:44:58) [*] Dumping section ".rsrc" in "calc.exe.sex/.rsrc-0x000000010007f000-403352-514048-lrw_.bin"
(2015-09-17 12:44:59) [*] Dumping section ".reloc" in "calc.exe.sex/.reloc-0x00000001000e2000-892-917504-lrw_.bin"
(2015-09-17 12:44:59) [*] Dumping exit points in "aux.ini"
(2015-09-17 12:44:59) [*] Dumping entry points in "aux.ini"
(2015-09-17 12:44:59) [*] Dumping relocations in "aux.ini"
(2015-09-17 12:45:00) [*] Dumping functions in "aux.ini"
(2015-09-17 12:45:00) [*] Done
```

The output informs us that a directory named **calc.exe.sex** that contains the
extracted sections was created.

```sh
$ ls -a1 calc.exe.sex/
.
..
.data-0x0000000100073000-19968-467968-lrw_.bin
.pdata-0x0000000100078000-25764-487936-lrw_.bin
.rdata-0x0000000100062000-69316-398336-lrw_.bin
.reloc-0x00000001000e2000-892-917504-lrw_.bin
.rsrc-0x000000010007f000-403352-514048-lrw_.bin
.text-0x0000000100001000-396489-1536-lr_x.bin
aux.ini
```

File **aux.ini** contains auxiliary information.

```sh
$ cat calc.exe.sex/aux.ini
[aux]
arch=x86_64

[exit_points]
exit_point0=0x100000225,shell32.dll!SHGetSpecialFolderPathW
exit_point1=0x100000195,shell32.dll!SHGetFolderPathW
exit_point2=0x100000282,shell32.dll!ShellAboutW
exit_point3=0x1000000a5,shell32.dll!<none>
...

[entry_points]
entry_point0=0x10001b9b8,<none>

[relocations]
relocation0=0x100062c40
relocation1=0x100062c48
relocation2=0x100062c50
relocation3=0x100062c58
...

[functions]
function0=0x100001000
function1=0x100001bd8
function2=0x100001c10
function3=0x100001c58
...
```

Given the path to the aforementioned directory, **sex_loader.py** loads the
files shown above and creates a list of classes that represent the dumped
sections, their load addresses, raw data and so on. It exports a class,
**SexLoader**, which can be used to read arbitrary amounts of data from a
section given a virtual address and a size.

For example, the code below will print the first 16 bytes of **.text**.

```python
from sex import sex_loader

sl = sex_loader.SexLoader('calc.exe.sex/')
print binascii.hexlify(sl.read(0x100001000, 16))
```

Information on individual sections is provided via **sl.sections** as shown
below:

```python
for section in sl.sections:
    print section.name
```

Exit points, entry points, relocations and functions can be accessed using the
following:

```python
print map(hex, sl.exit_points)
print map(hex, sl.entry_points)
print map(hex, sl.relocations)
print map(hex, sl.functions)
```

A dictionary of labels mapping addresses to symbolic names is available at
**sl.labels**.

```python
for address, name in sl.labels.items():
    print '0x%x %s' % (address, name)
```

For more information, have a look at **sex_loader.py**.

