# /bin/bash
. ./dirs.sh

# Deleting files
echo -e "   *** Deleting: " $cdir
rm $cdir/* 2> /dev/null

echo -e "   *** Deleting: " $vdir
rm $vdir/* 2> /dev/null

if [ "$1" == "all" ]; then
        echo -e "   *** Deleting: " $cadir
        rm $cadir/* 2> /dev/null
fi
                
if [ "$1" == "tpm" ]; then
# Clear TPM
echo -e "   *** Clearing TPM"
tpm2_clear
fi

