CONFIG_TEMPLATE=$1
CONFIG_OUTPUT=$2
GOSOP_BRANCH_V1=$3
GOSOP_BRANCH_V2=$4
GOSOP_MAIN_V1=$5
GOSOP_MAIN_V2=$6
cat $CONFIG_TEMPLATE \
    | sed "s@__GOSOP_BRANCH_V1__@${GOSOP_BRANCH_V1}@g" \
    | sed "s@__GOSOP_BRANCH_V2__@${GOSOP_BRANCH_V2}@g" \
    | sed "s@__GOSOP_MAIN_V1__@${GOSOP_MAIN_V1}@g" \
    | sed "s@__GOSOP_MAIN_V2__@${GOSOP_MAIN_V2}@g" \
    | sed "s@__SQOP__@${SQOP}@g" \
    | sed "s@__GPGME_SOP__@${GPGME_SOP}@g" \
    | sed "s@__SOP_OPENPGPJS__@${SOP_OPENPGPJS}@g" \
    | sed "s@__RNP_SOP__@${RNP_SOP}@g" \
    > $CONFIG_OUTPUT