import logging

import kopf

# Log-spam from liveness check
logging.getLogger("aiohttp.access").setLevel(logging.ERROR)

MAC_ANNOT = "netcup.noshoes.xyz/primary-mac"
SERVERNAME_ANNOT = "netcup.noshoes.xyz/server-name"

# Nodes to consider for failover ips need to have these annotations
NODE_ANNOTATIONS = {
    MAC_ANNOT: kopf.PRESENT,
    SERVERNAME_ANNOT: kopf.PRESENT,
}
