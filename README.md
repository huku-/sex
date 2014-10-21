# S.EX. a.k.a. Section EXtractor

huku &lt;[huku@grhack.net](mailto:huku@grhack.net)&gt;


## About

This is a small shell script I developed for personal use. It exports sections
from various executable formats (ELF, PE-COFF, FAT & Mach-O) and saves them in 
separate files named after the section in question. Filenames match the pattern
shown below:

```
$name-$vma-$size-$offset-$flags.bin
```

**$name** - Section name

**$vma** - Virtual memory address where the section is loaded at runtime

**$size** - Size of section in bytes

**$offset** - Offset of section data in the executable

**$flags** - Letters indicating if the section is loaded (**l**), readable
(**r**), writable (**w**) or executable (**x**)

Here's how it looks like when ran on a Debian system against */bin/ls*.

```
$ lsb_release -a
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 7.5 (wheezy)
Release:    7.5
Codename:   wheezy

$ ./sex.sh /bin/ls
[*] Creating directory "ls"
[*] /bin/ls: ELF
[*] Exporting section ".interp" in "ls/.interp-0x08048154-19-340-lrw_.bin"
[*] Exporting section ".note.ABI-tag" in "ls/.note.ABI_tag-0x08048168-32-360-lrw_.bin"
[*] Exporting section ".note.gnu.build-id" in "ls/.note.gnu.build_id-0x08048188-36-392-lrw_.bin"
[*] Exporting section ".hash" in "ls/.hash-0x080481ac-884-428-lrw_.bin"
[*] Exporting section ".gnu.hash" in "ls/.gnu.hash-0x08048520-100-1312-lrw_.bin"
[*] Exporting section ".dynsym" in "ls/.dynsym-0x08048584-1952-1412-lrw_.bin"
[*] Exporting section ".dynstr" in "ls/.dynstr-0x08048d24-1454-3364-lrw_.bin"
[*] Exporting section ".gnu.version" in "ls/.gnu.version-0x080492d2-244-4818-lrw_.bin"
[*] Exporting section ".gnu.version_r" in "ls/.gnu.version_r-0x080493c8-224-5064-lrw_.bin"
[*] Exporting section ".rel.dyn" in "ls/.rel.dyn-0x080494a8-40-5288-lrw_.bin"
[*] Exporting section ".rel.plt" in "ls/.rel.plt-0x080494d0-848-5328-lrw_.bin"
[*] Exporting section ".init" in "ls/.init-0x08049820-38-6176-lr_x.bin"
[*] Exporting section ".plt" in "ls/.plt-0x08049850-1712-6224-lr_x.bin"
[*] Exporting section ".text" in "ls/.text-0x08049f00-71932-7936-lr_x.bin"
[*] Exporting section ".fini" in "ls/.fini-0x0805b7fc-23-79868-lr_x.bin"
[*] Exporting section ".rodata" in "ls/.rodata-0x0805b820-16804-79904-lrw_.bin"
[*] Exporting section ".eh_frame_hdr" in "ls/.eh_frame_hdr-0x0805f9c4-1804-96708-lrw_.bin"
[*] Exporting section ".eh_frame" in "ls/.eh_frame-0x080600d0-10236-98512-lrw_.bin"
[*] Exporting section ".init_array" in "ls/.init_array-0x08063ed8-4-110296-lrw_.bin"
[*] Exporting section ".fini_array" in "ls/.fini_array-0x08063edc-4-110300-lrw_.bin"
[*] Exporting section ".jcr" in "ls/.jcr-0x08063ee0-4-110304-lrw_.bin"
[*] Exporting section ".dynamic" in "ls/.dynamic-0x08063ee4-264-110308-lrw_.bin"
[*] Exporting section ".got" in "ls/.got-0x08063fec-8-110572-lrw_.bin"
[*] Exporting section ".got.plt" in "ls/.got.plt-0x08063ff4-436-110580-lrw_.bin"
[*] Exporting section ".data" in "ls/.data-0x080641c0-300-111040-lrw_.bin"
[*] Done
```

The output informs us that a directory named *ls* is created containing the 
exported sections.

```
$ ls -a1 ls/
.
..
.data-0x080641c0-300-111040-lrw_.bin
.dynamic-0x08063ee4-264-110308-lrw_.bin
.dynstr-0x08048d24-1454-3364-lrw_.bin
.dynsym-0x08048584-1952-1412-lrw_.bin
.eh_frame-0x080600d0-10236-98512-lrw_.bin
.eh_frame_hdr-0x0805f9c4-1804-96708-lrw_.bin
.fini-0x0805b7fc-23-79868-lr_x.bin
.fini_array-0x08063edc-4-110300-lrw_.bin
.gnu.hash-0x08048520-100-1312-lrw_.bin
.gnu.version-0x080492d2-244-4818-lrw_.bin
.gnu.version_r-0x080493c8-224-5064-lrw_.bin
.got-0x08063fec-8-110572-lrw_.bin
.got.plt-0x08063ff4-436-110580-lrw_.bin
.hash-0x080481ac-884-428-lrw_.bin
.init-0x08049820-38-6176-lr_x.bin
.init_array-0x08063ed8-4-110296-lrw_.bin
.interp-0x08048154-19-340-lrw_.bin
.jcr-0x08063ee0-4-110304-lrw_.bin
.note.ABI_tag-0x08048168-32-360-lrw_.bin
.note.gnu.build_id-0x08048188-36-392-lrw_.bin
.plt-0x08049850-1712-6224-lr_x.bin
.rel.dyn-0x080494a8-40-5288-lrw_.bin
.rel.plt-0x080494d0-848-5328-lrw_.bin
.rodata-0x0805b820-16804-79904-lrw_.bin
.text-0x08049f00-71932-7936-lr_x.bin
```

Given the path to the aforementioned directory, **sex_loader.py** loads the
files shown above and creates a list of classes that represent the dumped
sections, their load addresses, raw data and so on. It exports a class,
**SexLoader**, which can be used to read arbitrary amounts of data from a
section given a virtual address and a size.

For example, the code below will print the contents of **.interp**.

```
import sex_loader

sl = sex_loader.SexLoader("ls/")
print sl.read(0x08048154, 19)
```

Information on individual sections is provided via **sl.sections** as shown
below.

```
for section in sl.sections:
    print section.name
```

For more information, have a look at **sex_loader.py**.

