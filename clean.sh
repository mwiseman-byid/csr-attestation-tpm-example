# /bin/bash
source ./dirs.sh

# Clear TPM
echo -e "Clearing TPM"
tpm2_clear

# Deleting files
echo -e "Deleting: " $cdir
rm $cdir/* 2> /dev/null

echo -e "Deleting: " $acadir
rm $acadir/* 2> /dev/null

if [ "$1" == "all" ]; then
        echo -e "Deleting: " $cadir
        rm $cadir/* 2> /del/null
fi

