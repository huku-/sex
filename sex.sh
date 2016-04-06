#!/bin/bash
# S.EX. (Section EXtractor) v1.0
#
# Extracts sections and auxiliary information from various executable file
# formats (ELF, PE-COFF, FAT & Mach-O).
#
# Section data dumped by "sex.sh" can be loaded and accessed by a Python class,
# named `SEXLoader', defined in "sex_loader.py".
#
# huku <huku@grhack.net>


# Path to `objdump' binary; see comment in `main()' for more information.
objdump=


# Writes a message prefixed by the current timestamp to the standard output.
#
# Arguments:
#
#     $1 - Message to write to the standard output.
#
# Returns:
#
#     $? - Undefined
#
function write_msg()
{
    local timestamp="$(date +"%Y-%m-%d %H:%M:%S")"
    echo "($timestamp) [*] $@"
}


# Checks that "$1" is a decimal number.
#
# Arguments:
#
#     $1 - The string to be checked.
#
# Returns:
#
#     $? - True if "$1" is a decimal number, false otherwise.
#
function is_decimal()
{
    local r=1
    if [[ "$1" =~ ^(\+|\-)?[1-9][0-9]*$ ]]; then
        r=0
    fi
    return $r
}


# Checks that "$1" is a hexadecimal number.
#
# Arguments:
#
#     $1 - The string to be checked.
#
# Returns:
#
#     $? - True if "$1" is a hexadecimal number, false otherwise.
#
function is_hexadecimal()
{
    local r=1
    if [[ "$1" =~ ^(0x)?[0-9a-fA-F]+$ ]]; then
        r=0
    fi
    return $r
}


# Dumps the architecture name of the executable file in "aux.ini".
#
# Arguments:
#
#     $1 - Full path to executable.
#     $2 - Directory where "aux.ini" will be created.
#
# Returns:
#
#     $? - Undefined
#
function dump_arch()
{
    local out="$(file "$1")"
    echo "[aux]" > "$2/aux.ini"
    if echo $out | egrep "([xX]86[_-]64|PE32\+)" &>/dev/null; then
        echo "arch=x86_64" >> "$2/aux.ini"
    elif echo $out | egrep "([iI][2-6]86|[iI]ntel 80.?86|PE32)" &>/dev/null; then
        echo "arch=i386" >> "$2/aux.ini"
    fi
    echo "" >> "$2/aux.ini"
}


# Check if the specified file is a PE-COFF executable.
#
# Arguments:
#
#     $1 - Full path to the file to check.
#
# Returns:
#
#     $? - True if the given file is a PE-COFF, false otherwise.
#
function is_pe_coff()
{
    local ret=1
    local magic="$(hexdump -e '2/1 "%x" "\n"' -n 2 $1)"
    if [[ "$magic" == "4d5a" ]]; then
        ret=0
    fi
    return $ret
}


# Dumps the sections of a PE-COFF executable in separate files. I originally
# used `objdump' to do this, but the information returned is incomplete (actual
# versus virtual size of sections etc). To solve this problem, I had to write
# the following custom parser.
#
# Arguments:
#
#     $1 - Full path to PE-COFF executable.
#     $2 - Directory to save files to.
#
# Returns:
#
#     $? - Undefined
#
function dump_pe_coff
{
    local image_base="0x$("$objdump" -p "$1" | awk '/^ImageBase/ { print $2 }')"

    # Compute offset to PE header and size of optional header.
    local pe_off="$(hexdump -s 60 -n 4 -e "1/4 \"0x%x\\n\"" "$1")"
    local opt_sz="$(hexdump -s "$(($pe_off + 20))" -n 2 -e "1/2 \"0x%x\\n\"" "$1")"

    # Compute offset to section headers, number of sections and total size of
    # section headers.
    local sect_off="$(($pe_off + 24 + $opt_sz))"
    local sect_cnt="$(hexdump -s "$(($pe_off + 6))" -n 2 -e "1/2 \"0x%x\\n\"" "$1")"
    local sect_sz="$(($sect_cnt * 40))"

    hexdump -s "$sect_off" -n "$sect_sz" -e "\"%.8s \" 8/4 \"%d \" \"\\n\"" "$1" | \
            while read name vsize vma size offset _ _ _ flags; do

        local r="_"
        if (("$flags" & 0x40000000)); then
            r="r"
        fi

        local x="_"
        if (("$flags" & 0x20000000)); then
            x="x"
        fi

        local w="_"
        if (("$flags" & 0x80000000)); then
            r="r"
            w="w"
        fi

        # Compute virtual memory address to hexadecimal.
        vma="$(printf "0x%x" "$(($vma + $image_base))")"
        local filename="$2/${name//\-/_}-$vma-$vsize-$offset-l$r$w$x.bin"

        write_msg "Dumping section \"$name\" in \"$filename\""
        if [[ "$vsize" -gt "$size" ]]; then
            dd if=$1 of=$filename bs=1 skip=$offset count=$size &>/dev/null

            # The section's virtual size may be larger than the actual size of
            # raw data. In this case the section is padded with zeros.
            write_msg "Padding \"$name\" with zeros: $size => $vsize"
            dd if=/dev/zero of=$filename bs=1 seek=$size count=$(($vsize - $size)) \
                conv=notrunc &>/dev/null
        else
            dd if=$1 of=$filename bs=1 skip=$offset count=$vsize &>/dev/null
        fi
    done
}


# Dumps PE-COFF imports in "aux.ini".
#
# Arguments:
#
#     $1 - Full path to the PE-COFF file.
#     $2 - Directory where "aux.ini" was created.
#
# Returns:
#
#     $? - Undefined
#
function dump_pe_coff_exit_points()
{
    local tempfile="$(mktemp -q "${TMP:-/tmp}/sex-XXXXXXXX")"
    cat > "$tempfile" << EOF
BEGIN {
    num = 0
}

/^Magic/ {
    if(index(\$0, "PE32+") > 0)
        thunk_size = 8
    else
        thunk_size = 4
}

/^ImageBase/ {
    image_base = int("0x" \$2)
}

/^([[:space:]]+[[:xdigit:]]+){6}$/ {
    thunk_address = int("0x" \$6)
    if(thunk_address != 0)
        thunk_address += image_base
}

/DLL Name/ {
    name = tolower(substr(\$0, match(\$0, ": ") + 2))
    getline
    getline

    while(!match(\$0, /^$/)) {
        print sprintf("exit_point%d=0x%lx,%s!%s", num, thunk_address, name, \$3)
        num += 1
        thunk_address += thunk_size
        getline
    }
}
EOF

    echo "[exit_points]" >> "$2/aux.ini"
    "$objdump" -p "$1" | awk -f "$tempfile" >> "$2/aux.ini"
    echo "" >> "$2/aux.ini"

    rm -fr "$tempfile"
}


# Dumps PE-COFF exports in "aux.ini".
#
# Arguments:
#
#     $1 - Full path to the PE-COFF file.
#     $2 - Directory where "aux.ini" was created.
#
# Returns:
#
#     $? - Undefined
#
function dump_pe_coff_entry_points()
{
    local tempfile="$(mktemp -q "${TMP:-/tmp}/sex-XXXXXXXX")"
    cat > "$tempfile" << EOF
BEGIN {
    num = 0
}

/AddressOfEntryPoint/ {
    entry_point = int("0x" \$2)
}

/^ImageBase/ {
    image_base = int("0x" \$2)
}

/Export Address Table --/ {
    getline
    num = 0
    while(!match(\$0, /^$/)) {
        split(\$0, tmp1, "] ")
        split(tmp1[3], tmp2)
        addresses[num] = int("0x" tmp2[1]) + image_base
        num += 1
        getline
    }
}

/\[Ordinal\/Name Pointer\] Table/ {
    getline
    num = 0
    while(!match(\$0, /^$/)) {
        split(\$0, tmp1, "] ")
        names[num] = tmp1[2]
        num += 1
        getline
    }
}

END {
    addresses[num] = image_base + entry_point
    names[num] = "<none>"
    for(num = 0; num < length(addresses); num += 1) {
        print sprintf("entry_point%d=0x%lx,%s", num, addresses[num], names[num])
    }
}
EOF

    echo "[entry_points]" >> "$2/aux.ini"
    "$objdump" -p "$1" | awk -f "$tempfile" >> "$2/aux.ini"
    echo "" >> "$2/aux.ini"

    rm -fr "$tempfile"
}


# Parse the relocations of a PE-COFF and write them in "aux.ini". Unfortunately
# `objdump' is buggy and won't parse ".reloc" sections of XCOFF files correctly.
#
# Arguments:
#
#     $1 - Full path to the PE-COFF file.
#     $2 - Directory where "aux.ini" was created.
#
# Returns:
#
#     $? - Undefined
#
function dump_pe_coff_relocations()
{
    local image_base="0x$("$objdump" -p "$1" | awk '/^ImageBase/ { print $2 }')"

    echo "[relocations]" >> "$2/aux.ini"

    # Check if we have extracted a section whose name starts with ".reloc-".
    if [ -f "$2/".reloc* ]; then
        local filename="$(echo "$2"/.reloc*)"
        local offset=0
        local num=0

        local rva=
        local block_size=
        local relocs=
        while true; do

            # Read block RVA.
            rva="$(hexdump -s "$offset" -e '"%u"' -n 4 "$filename")"
            offset=$(($offset + 4))

            # Read block size.
            block_size="$(hexdump -s "$offset" -e '"%u"' -n 4 "$filename")"
            offset=$(($offset + 4))

            # A zero RVA or block size indicates that we should stop parsing the
            # relocation section.
            if ! is_decimal "$rva" || [[ "$rva" -eq 0 ]]; then
                break
            fi
            if ! is_decimal "$block_size" || [[ "$block_size" -eq 0 ]]; then
                break
            fi

            # Subtract the block header size from the overall block size.
            block_size=$(($block_size - 8))

            # Dump all relocations for this RVA with one command. Makes the
            # whole process much faster than dumping relocations one by one.
            relocs="$(hexdump -s "$offset" -e "$(($block_size / 2))/2 \"0x%x\\n\"" \
                -n "$block_size" "$filename")"

            for reloc in $relocs; do
                # XXX: Handle other relocation types?
                if [[ "$(($reloc >> 12))" -eq 3 ]]; then
                    reloc="$(($image_base + $rva + ($reloc & 0x0fff)))"
                    printf "relocation%d=0x%x\n" "$num" "$reloc" >> "$2/aux.ini"
                    num=$(($num + 1))
                fi
            done

            offset=$(($offset + $block_size))
        done
    fi

    echo "" >> "$2/aux.ini"
}


# Dump PE-COFF executable functions from ".pdata" in "aux.ini".
#
# Arguments:
#
#     $1 - Full path to the PE-COFF file.
#     $2 - Directory where "aux.ini" was created.
#
# Returns:
#
#     $? - Undefined
#
function dump_pe_coff_functions()
{
    local tempfile="$(mktemp -q "${TMP:-/tmp}/sex-XXXXXXXX")"
    cat > "$tempfile" << EOF
/The Function Table/ {
    getline
    getline

    num = 0
    while(!match(\$0, /^$/)) {
        print sprintf("function%d=0x%lx", num, int("0x" \$2))
        num += 1
        getline
    }
}
EOF

    echo "[functions]" >> "$2/aux.ini"
    "$objdump" -p "$1" | awk -f "$tempfile" >> "$2/aux.ini"
    echo "" >> "$2/aux.ini"

    rm -fr "$tempfile"
}


# Check if the specified file is an ELF executable.
#
# Arguments:
#
#     $1 - Full path to the file to check.
#
# Returns:
#
#     $? - True if the given file is an ELF, false otherwise.
#
function is_elf()
{
    local ret=1
    local magic="$(hexdump -e '4/1 "%x" "\n"' -n 4 $1)"
    if [[ "$magic" == "7f454c46" ]]; then
        ret=0
    fi
    return $ret
}


# Dumps the sections of an ELF executable in separate files.
#
# Arguments:
#
#     $1 - Full path to ELF executable.
#     $2 - Directory to save files to.
#
# Returns:
#
#     $? - Undefined
#
function dump_elf()
{
    "$objdump" -w -h "$1" | egrep "^[[:space:]]+[[:digit:]]" | \
            while read idx name size vma lma offset align flags; do
        offset="$(printf "%d" 0x$offset)"
        size="$(printf "%d" 0x$size)"

        local l="_"
        if [[ "$flags" =~ LOAD ]]; then
            l="l"
        fi

        local r="_"
        if [[ "$flags" =~ READONLY ]]; then
            r="r"
        fi

        local x="_"
        if [[ "$flags" =~ CODE ]]; then
            x="x"
        fi

        local w="_"
        if [[ "$flags" =~ DATA ]]; then
            r="r"
            w="w"
        fi

        if [[ "$flags" =~ CONTENTS ]]; then
            local filename="$2/${name//\-/_}-0x$vma-$size-$offset-$l$r$w$x.bin"
            write_msg "Dumping section \"$name\" in \"$filename\""
            dd if=$1 of=$filename bs=1 skip=$offset count=$size &>/dev/null
        fi
    done
}


# Check if the specified file is a MacOS FAT executable.
#
# Arguments:
#
#     $1 - Full path to the file to check.
#
# Returns:
#
#     $? - True if the given file is a FAT, false otherwise.
#
function is_fat()
{
    local ret=1
    local magic="$(hexdump -e '4/1 "%x" "\n"' -n 4 $1)"
    if [[ "$magic" == "cafebabe" || "$magic" == "bebafeca" ]]; then
        ret=0
    fi
    return $ret
}


# Check if the specified file is a Mach-O executable.
#
# Arguments:
#
#     $1 - Full path to the file to check.
#
# Returns:
#
#     $? - True if the given file is a Mach-O, false otherwise.
#
function is_macho()
{
    local ret=1
    local magic="$(hexdump -e '4/1 "%x" "\n"' -n 4 $1)"
    if [[ "$magic" =~ feedfac[ef] || "$magic" =~ c[ef]faedfe ]]; then
        ret=0
    fi
    return $ret
}


# Dumps the sections of a Mach-O executable in separate files.
#
# Arguments:
#
#     $1 - Full path to Mach-O executable.
#     $2 - Directory to save files to.
#
# Returns:
#
#     $? - Undefined
#
dump_macho()
{
    otool -l "$1" | while read line; do
        if [[ "$line" =~ LC_SEGMENT(_64)?$ ]]; then
            while [[ ! "$line" =~ initprot ]]; do
                read line
            done
            local initprot="$(printf "%d" 0x${line##*0x})"

            local l="_"
            if [[ $initprot != 0 ]]; then
                l="l"
            fi

            local r="_"
            if [[ $(($initprot & 1)) != 0 ]]; then
                r="r"
            fi

            local w="_"
            if [[ $(($initprot & 2)) != 0 ]]; then
                w="w"
            fi

            local x="_"
            if [[ $(($initprot & 4)) != 0 ]]; then
                x="x"
            fi
        elif [[ "$line" =~ ^Section ]]; then
            read _ sectname
            read _ segname
            read _ addr
            read _ size
            read _ offset

            size="$(printf "%d" $size)"
            local filename="$2/$segname.$sectname-$addr-$size-$offset-$l$r$w$x.bin"

            write_msg "Dumping section \"$segname.$sectname\" to \"$filename\""
            dd if="$1" of="$filename" bs=1 count=$size skip=$offset &>/dev/null
        fi
    done
}


function main()
{
    if [[ $# -lt 1 ]]; then
        echo "$0 <file(s)>"
    else
        # Resolve full path to `objdump'. On MacOS X, some package management
        # tools install `objdump' as `gobjdump'.
        objdump="$(which objdump || which gobjdump)"
        if [[ -z "$objdump" ]]; then
            write_msg "Cannot find objdump or gobjdump binary"
            return
        fi

        while [[ "$1" ]]; do
            local dir="$(basename $1).sex"
            write_msg "Creating directory \"$dir\""
            mkdir "$dir" &>/dev/null

            write_msg "Storing auxiliary information in \"$dir/aux.ini\""
            dump_arch "$1" "$dir"

            if is_elf "$1"; then
                write_msg "$1: ELF"
                dump_elf "$1" "$dir"

            elif is_pe_coff "$1"; then
                write_msg "$1: PE-COFF"
                dump_pe_coff "$1" "$dir"

                write_msg "Dumping exit points in \"aux.ini\""
                dump_pe_coff_exit_points "$1" "$dir"

                write_msg "Dumping entry points in \"aux.ini\""
                dump_pe_coff_entry_points "$1" "$dir"

                write_msg "Dumping relocations in \"aux.ini\""
                dump_pe_coff_relocations "$1" "$dir"

                write_msg "Dumping functions in \"aux.ini\""
                dump_pe_coff_functions "$1" "$dir"

            elif is_fat "$1"; then
                write_msg "$1: FAT"

                # Read list of architectures in FAT executable.
                local archs="$(lipo -detailed_info "$1" | awk '/^architecture/ { print $2 }')"

                # Export one architecture at a time and store the results in
                # subdirectories under "$dir/".
                for arch in $archs; do
                    local out="$dir.$arch.bin"
                    write_msg "Extracting architecture \"$arch\" in \"$out\""
                    lipo -extract "$arch" -output "$out" "$1" &>/dev/null

                    mkdir "$dir/$arch" &>/dev/null
                    dump_macho "$out" "$dir/$arch"

                    rm -fr "$out"
                done

            elif is_macho "$1"; then
                write_msg "$1: Mach-O"
                dump_macho "$1" "$dir"

            else
                write_msg "$1: Unknown architecture"
            fi
            shift
        done
        write_msg "Done"
    fi
}


main $@

# EOF

