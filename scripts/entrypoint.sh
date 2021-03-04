#!/bin/bash

set -euo pipefail

CONFIG_DIR="/openair-smf/etc"

for c in ${CONFIG_DIR}/*.conf; do
    # grep variable names (format: ${VAR}) from template to be rendered
    VARS=$(grep -oP '@[a-zA-Z0-9_]+@' ${c} | sort | uniq | xargs)
    echo "Now setting these variables '${VARS}'"

    # create sed expressions for substituting each occurrence of ${VAR}
    # with the value of the environment variable "VAR"
    EXPRESSIONS=""
    for v in ${VARS}; do
<<<<<<< HEAD
        NEW_VAR=`echo $v | sed -e "s#@##g"`
=======
    NEW_VAR=`echo $v | sed -e "s#@##g"`
>>>>>>> 2409d789898b1ac60fcc6f7d0e2a67cafb66f3ba
        if [[ -z ${!NEW_VAR+x} ]]; then
            echo "Error: Environment variable '${NEW_VAR}' is not set." \
                "Config file '$(basename $c)' requires all of $VARS."
            exit 1
        fi
        EXPRESSIONS="${EXPRESSIONS};s|${v}|${!NEW_VAR}|g"
    done
    EXPRESSIONS="${EXPRESSIONS#';'}"

    # render template and inline replace config file
    sed -i "${EXPRESSIONS}" ${c}
done
echo "Done setting the configuration"
<<<<<<< HEAD
exec "$@"
=======
exec "$@"
>>>>>>> 2409d789898b1ac60fcc6f7d0e2a67cafb66f3ba
