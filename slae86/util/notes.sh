
# gets shellcode
# https://epi052.gitlab.io/notes-to-self/blog/2018-08-01-python3-rolling-xor-encoder-with-x64-decoder-stub/
dump-shellcode () {
    # alternative, better?..
    # objdump -d insertion_decode | grep -v "<" | grep -oP '[a-f0-9]{2} ' --color=never | tr -d '\n' | sed 's/ /\\x/g' | sed 's/\\x$//g' | sed 's/^/\\x/g' 
    objdump -d "$1" |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
}

dump-shellcodeV2() {
    objdump -d ./custom_decode |grep '[0-9a-f]:' | grep -v file | cut -d':' -f2- | sed 's/^\W*//g' | grep -Po "^([0-9a-f]{2} )+" | tr -d '\n' | sed 's/\W/\\x/g' | sed 's/^/\\x/g' | rev | cut -c3- |rev
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

ip2hex () {
    python3 -c "print('push 0x' + ''.join([hex(int(x)+256)[3:] for x in '$1'.split('.')][::-1]) + '\t\t; IP = $1 (little endian)')"
}

num2hex() {
    # requires endian()
    tmp=$(printf "%.8x" $1 | endian | sed 's/0*$//g')
    printf "push word 0x$tmp\t\t; num = '"$1"' (little endian)\n" $1
}

