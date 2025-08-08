import logging
import os

import kopf

from netcup_foip_operator import MAC_ANNOT, NODE_ANNOTATIONS


def ensure_ip_assigned(mac: str, ip: str):
    logging.info(f"Adding {ip} to interface with {mac}")


@kopf.on.startup()
async def configure(memo: kopf.Memo, settings: kopf.OperatorSettings, **_):
    settings.posting.enabled = False
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        key="last-handled-node-interface",
    )

    node_name = os.environ.get("NODE_NAME")
    if not node_name:
        logging.error("NODE_NAME env var not set, this operator won't do anything!")
        exit(1)
    else:
        memo.node_name = node_name


@kopf.index("failoverip.netcup.noshoes.xyz", field=["spec.ip", "name"])
async def failover_ips(name: str | None, spec: kopf.Spec, **_):
    return {name: spec.get("ip")}


@kopf.index(
    "node", field=["name", f"annotations.{MAC_ANNOT}"], annotations=NODE_ANNOTATIONS
)
async def node_macs(name: str | None, annotations: kopf.Annotations, **_):
    return {name: annotations[MAC_ANNOT]}


# @kopf.on.create("node", annotations=NODE_ANNOTATIONS)
# @kopf.on.update("node", field=f"annotations.{MAC_ANNOT}", annotations=NODE_ANNOTATIONS)
async def node(
    memo: kopf.Memo,
    annotations: kopf.Annotations,
    name: str | None,
    **kwargs,
):
    failover_ips: kopf.Index = kwargs["failover_ips"]
    if name == memo.node_name and (mac := annotations.get(MAC_ANNOT, None)):
        for (ip,) in failover_ips.values():
            ensure_ip_assigned(mac, ip)


@kopf.on.resume("failoverip.netcup.noshoes.xyz")
@kopf.on.create("failoverip.netcup.noshoes.xyz")
@kopf.on.update("failoverip.netcup.noshoes.xyz", field="spec")
async def foip(memo: kopf.Memo, spec: kopf.Spec, **kwargs):
    # This needs to be an entirely separate controller, because the foip controller will
    # ideally only run on one instance, whereas the ip address assignment needs to happen
    # on all nodes!
    # On the up-side, this makes everything a lot easier, we just listen to
    # changes of the foips and assign them on any interface with a suitable mac
    node_macs: kopf.Index = kwargs["node_macs"]
    if (macs := node_macs.get(memo.node_name, None)) and (ip := spec.get("ip")):
        (mac,) = macs
        ensure_ip_assigned(mac, ip)
