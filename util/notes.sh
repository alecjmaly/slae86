
# gets shellcode
getSC () {
    # alternative, better?..
    # objdump -d insertion_decode | grep -v "<" | grep -oP '[a-f0-9]{2} ' --color=never | tr -d '\n' | sed 's/ /\\x/g' | sed 's/\\x$//g' | sed 's/^/\\x/g' 
    objdump -d "$1" |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
}


endian () {
    #!/bin/bash

    # check stdin
    if [ -t 0 ]; then exit; fi

    v=`cat /dev/stdin`
    i=${#v}

    while [ $i -gt 0 ]
    do
        i=$[$i-2]
        echo -n ${v:$i:2}
    done

    echo
}

iptohex () {
    python3 -c "print('push 0x' + ''.join([hex(int(x)+256)[3:] for x in '$1'.split('.')][::-1]) + '\t\t; IP = $1 (little endian)')"
}

numtohex() {
    # requires endian()
    tmp=$(printf "%.8x" $1 | endian | sed 's/0*$//g')
    printf "push word 0x$tmp\t\t; num = '"$1"' (little endian)\n" $1
}