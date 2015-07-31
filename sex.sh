#!/bin/bash
# S.EX. (Section EXtractor) v1.0
#
# Extracts sections from various executable formats (ELF, PE-COFF, FAT & Mach-O)
# and saves them in separate files named after the corresponding section.
#
# Section data dumped by "sex.sh" can be loaded and accessed by a Python class,
# named `SEXLoader', defined in "sex_loader.py".
#
# huku <huku@grhack.net>


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


# Dumps the architecture name of the executable file in "aux.txt".
#
# Arguments:
#
#     $1 - Full path to executable.
#     $2 - Directory where "aux.txt" will be created.
#
# Returns:
#
#     $? - Undefined
#
function dump_arch()
{
    local out="$(file "$1")"
    if echo $out | egrep "[xX]86[_-]64" &>/dev/null; then
        echo "x86_64" > "$2/aux.txt"
    elif echo $out | egrep "([iI][2-6]86|[iI]ntel 80.?86)" &>/dev/null; then
        echo "i386" > "$2/aux.txt"
    fi
}


# Dumps the sections of an ELF or PE-COFF executable in separate files.
#
# Arguments:
#
#     $1 - Full path to ELF or PE-COFF executable.
#     $2 - Directory to save files to.
#
# Returns:
#
#     $? - Undefined
#
function dump_objdump()
{
    dump_arch "$1" "$2"

    objdump -w -h "$1" | egrep "^[[:space:]]+[[:digit:]]" | \
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
        if  [[ "$flags" =~ CODE ]]; then
            x="x"
        fi

        local w="_"
        if [[ "$flags" =~ DATA ]]; then
            r="r"
            w="w"
        fi

        if [[ "$flags" =~ CONTENTS ]]; then
            local filename="$2/${name//\-/_}-0x$vma-$size-$offset-$l$r$w$x.bin"
            write_msg "Exporting section \"$name\" in \"$filename\""
            dd if=$1 of=$filename bs=1 skip=$offset count=$size &>/dev/null
        fi
    done
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
dump_otool()
{
    dump_arch "$1" "$2"

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

            write_msg \
                "Extracting section \"$segname.$sectname\" to \"$filename\""
            dd if="$1" of="$filename" bs=1 count=$size skip=$offset &>/dev/null
        fi
    done
}


function main()
{
    if [[ $# -lt 1 ]]; then
        echo "$0 <file(s)>"
    else
        while [[ "$1" ]]; do
            local dir="$(basename $1)"
            write_msg "Creating directory \"$dir\""
            mkdir "$dir" &>/dev/null

            if is_elf "$1"; then
                write_msg "$1: ELF"
                dump_objdump "$1" "$dir"

            elif is_pe_coff "$1"; then
                write_msg "$1: PE-COFF"
                dump_objdump "$1" "$dir"

            elif is_fat "$1"; then
                write_msg "$1: FAT"

                # Read list of architectures in FAT executable.
                local archs="$(lipo -detailed_info "$1" | egrep "^architecture" | \
                    cut -d " " -f 2)"

                # Export one architecture at a time and store the results in
                # subdirectories under "$dir/".
                for arch in $archs; do
                    local out="$dir.$arch.bin"
                    write_msg "Extracting architecture \"$arch\" in \"$out\""
                    lipo -extract "$arch" -output "$out" "$1" &>/dev/null

                    mkdir "$dir/$arch" &>/dev/null
                    dump_otool "$out" "$dir/$arch"

                    rm -fr "$out"
                done

            elif is_macho "$1"; then
                write_msg "$1: Mach-O"
                dump_otool "$1" "$dir"

            else
                write_msg "$1: unknown architecture"
            fi
            shift
        done
        write_msg "Done"
    fi
}


main $@

# EOF
