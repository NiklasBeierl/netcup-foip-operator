import logging
import os

import kopf
from pyroute2 import NDB
from pyroute2.ndb.objects.interface import SyncInterface

from netcup_foip_operator import MAC_ANNOT, NODE_ANNOTATIONS


def get_ifname_with_mac(ndb: NDB, mac: str) -> str | None:
    for interface in ndb.interfaces:
        if interface.address.lower() == mac.lower():
            return interface.ifname

    return None


async def ensure_ip_assigned(mac: str, ip: str):
    with NDB() as ndb:
        ifname = get_ifname_with_mac(ndb, mac)
        if ifname is None:
            logging.error(f"Could not find interface with MAC {mac}")
            return

        iface: SyncInterface
        with ndb.interfaces[ifname] as iface:
            if iface.ipaddr.exists(ip):
                logging.info(f"Interface {ifname} already has {ip}")
            else:
                iface.ensure_ip(ip)
                logging.info(f"Assigned {ip} to {ifname} ({mac})")


@kopf.on.startup()
async def configure(memo: kopf.Memo, settings: kopf.OperatorSettings, **_):
    settings.posting.enabled = False

    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix="netcup.noshoes.xyz", key="last-handled-node-interface"
    )
    settings.persistence.finalizer = "netcup.noshoes.xyz/node-interface"

    node_name = os.environ.get("NODE_NAME")
    if not node_name:
        logging.error("NODE_NAME env var not set, this operator won't do anything!")
        exit(1)
    else:
        memo.node_name = node_name


@kopf.index(
    "failoverip.netcup.noshoes.xyz",
    field=["spec.ip"],
)
async def failover_ips(name: str | None, spec: kopf.Spec, **_):
    return {name: spec.get("ip")}


@kopf.index(
    "node",
    annotations=NODE_ANNOTATIONS,
)
async def node_macs(name: str | None, annotations: kopf.Annotations, **_):
    return {name: annotations[MAC_ANNOT]}


# If a node is deleted we probably aren't running on it anymore :)
@kopf.on.create(
    "node",
    annotations=NODE_ANNOTATIONS,
)
@kopf.on.update(
    "node",
    field=f"annotations.{MAC_ANNOT}",
    annotations=NODE_ANNOTATIONS,
)
async def node(
    memo: kopf.Memo,
    annotations: kopf.Annotations,
    name: str | None,
    **kwargs,
):
    failover_ips: kopf.Index = kwargs["failover_ips"]
    if name == memo.node_name:
        # Local mac annotation changed
        mac = annotations.get(MAC_ANNOT)
        assert mac is not None

        for (ip,) in failover_ips.values():
            await ensure_ip_assigned(mac, ip)


# @kopf.on.delete("failoverip.netcup.noshoes.xyz")
@kopf.on.resume("failoverip.netcup.noshoes.xyz")
@kopf.on.create("failoverip.netcup.noshoes.xyz")
@kopf.on.update(
    "failoverip.netcup.noshoes.xyz",
    field="spec.ip",
)
async def foip(memo: kopf.Memo, spec: kopf.Spec, **kwargs):
    ip = spec.get("ip")
    assert ip is not None
    node_macs: kopf.Index = kwargs["node_macs"]
    if macs := node_macs.get(memo.node_name, None):
        # There should only be one
        (mac,) = macs
        await ensure_ip_assigned(mac, ip)
