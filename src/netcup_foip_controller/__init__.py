from base64 import b64decode
import logging
import random
from asyncio import Lock
from zeep import Client

import kopf
from cloudcoil.models.kubernetes.core.v1 import Secret, Node

from netcup_foip_controller.models.v1 import FailoverIp, FailoverIpStatus

SOAP_ADDR = "https://www.servercontrolpanel.de/WSEndUser?wsdl"
MAC_ANNOT = "netcup.noshoes.xyz/primary-mac"
SERVERNAME_ANNOT = "netcup.noshoes.xyz/server-name"

# Nodes to consider for failover ips need to have these annotations
NODE_ANNOTATIONS = {
    MAC_ANNOT: kopf.PRESENT,
    SERVERNAME_ANNOT: kopf.PRESENT,
}


@kopf.on.startup()
async def configure(memo: kopf.Memo, settings: kopf.OperatorSettings, **_):
    # Peering to ensure only instance is running
    settings.peering.name = "netcup-failover-ip"
    # TODO: Use better source for prio
    settings.peering.priority = int(random.random() * 1000)
    settings.peering.clusterwide = True
    settings.peering.mandatory = True
    settings.execution.max_workers = 1

    # Prevent async races when changing a failover ip
    memo.change_lock = Lock()


# Conditions and corresponding values that will cause the ip to be rerouted
BAD_CONDITIONS = (
    ("NetworkUnavailable", "True"),
    ("Ready", "False"),
    ("Ready", "Unknown"),
    ("PIDPressure", "True"),
    ("MemoryPressure", "True"),
    ("DiskPressure", "True"),
)

# The issues are spelled out explicitly here because they are ordered by "severity".
# Any of these issues present on a node will cause the operator to evaluate
# re-assignment. When reassigning, we pick the node with the least severe issue(s)
ISSUES = (
    # Networking broken
    "conditions.NetworkUnavailable=True",
    # Node (probably) lost
    "conditions.Ready=False",
    "conditions.Ready=Unknown",
    # None of the conditions but marked as unschedulable, probably cordoned...
    "spec.unschedulable",
    # System resource pressures might indicate approaching failure
    "conditions.PIDPressure=True",
    "conditions.MemoryPressure=True",
    "conditions.DiskPressure=True",
)

assert all(
    f"conditions.{cond}={bad_value}" in ISSUES for cond, bad_value in BAD_CONDITIONS
)

# How the nodes are sorted to choose the "best" node ...
SORTING = ISSUES + (
    "name",  # ... used as a tiebreaker
)


@kopf.index(
    "node",
    annotations=NODE_ANNOTATIONS,
)
async def node_data(name, status, spec, annotations, **_):
    data = {
        "name": name,
        "mac": annotations[MAC_ANNOT],
        "servername": annotations[SERVERNAME_ANNOT],
        "spec.unschedulable": spec.get("unschedulable", False),
    }

    existing_conditions = {
        cond["type"]: cond["status"] for cond in status["conditions"]
    }
    for cond, bad_value in BAD_CONDITIONS:
        is_bad = str(existing_conditions.get(cond, None)) == bad_value
        data[f"conditions.{cond}={bad_value}"] = is_bad

    return {name: data}


def get_better_node(node_index: kopf.Index, current: str | None = None) -> str | None:
    # Build tuples to rank the nodes
    as_tuples = {}
    for name, store in node_index.items():
        for node in store:
            as_tuples[node["name"]] = tuple(node[att] for att in SORTING)

    best = next(iter(sorted(as_tuples.values())))

    # Is the other node really better or does it just come sooner in the alphabet?
    if current is not None and (best[:-1] == as_tuples[current][:-1]):
        return None

    *_, name = best
    return name


@kopf.index("failoverip.netcup.noshoes.xyz")
async def failover_ips_by_node(name, status, **_):
    return {status.get("assignedNodeName"): name}


@kopf.on.create("node", annotations=NODE_ANNOTATIONS)
@kopf.on.update(
    "node",
    field="spec.unschedulable",
    annotations=NODE_ANNOTATIONS,
)
@kopf.on.update(
    "node",
    field="status.conditions",
    annotations=NODE_ANNOTATIONS,
)
@kopf.on.update(
    "node",
    field=f"annotations.{MAC_ANNOT}",
)
@kopf.on.update(
    "node",
    field=f"annotations.{SERVERNAME_ANNOT}",
)
@kopf.on.delete("node", annotations=NODE_ANNOTATIONS)
async def node(memo: kopf.Memo, reason: str, name: str | None, **kwargs):
    assert name is not None

    node_data: kopf.Index = kwargs["node_data"]
    failover_ips_by_node: kopf.Index = kwargs["failover_ips_by_node"]

    for node_name, foips in list(failover_ips_by_node.items()):
        for ip in foips:
            current = node_name

            if reason == "delete" and node_name == name:
                current = None

            better_node = get_better_node(node_data, current=current)
            if better_node is not None:
                logging.info(
                    f"Will assign {ip} to {better_node} due to node {reason}"
                )
                await assign_node(ip, better_node, memo.change_lock)


async def assign_node(ip_name: str, better_node: str, lock: Lock):
    failover_ip = FailoverIp.get(name=ip_name)
    secret = Secret.get(name=failover_ip.spec.secret_name)
    node = Node.get(name=better_node)
    assert failover_ip is not None
    assert secret is not None
    assert node is not None
    assert node.metadata is not None
    assert node.metadata.annotations is not None
    mac = node.metadata.annotations[MAC_ANNOT]
    vserver_name = node.metadata.annotations[SERVERNAME_ANNOT]
    ip = failover_ip.spec.ip
    assert secret.data is not None
    login_name = b64decode(secret.data["loginName"]).decode()
    password = b64decode(secret.data["password"]).decode()

    async with lock:
        client = Client(SOAP_ADDR)
        result = client.service.getVServerIPs(
            loginName=login_name,
            password=password,
            vserverName=vserver_name,
        )
        if ip in result:
            logging.warn(f"{ip} already assigned to {better_node} in netcup.")
        else:
            try:
                client.service.changeIPRouting(
                    loginName=login_name,
                    password=password,
                    routedIP=ip,
                    routedMask=32,
                    destinationVserverName=vserver_name,
                    destinationInterfaceMAC=mac,
                )
            except Exception as ex:
                raise

        if failover_ip.status is None:
            failover_ip.status = FailoverIpStatus()
        failover_ip.status.assigned_node_name = better_node
        await failover_ip.async_update()

    logging.info(f"Assigned {ip_name} to {better_node}")


# TODO: Unassign foip if crd deleted...
# @kopf.on.delete("failoverip.netcup.noshoes.xyz")
@kopf.on.resume("failoverip.netcup.noshoes.xyz")
@kopf.on.create("failoverip.netcup.noshoes.xyz")
@kopf.on.update("failoverip.netcup.noshoes.xyz", field="spec")
async def foip(reason: str, memo: kopf.Memo, name: str | None, status, **kwargs):
    assert name is not None

    node_data: kopf.Index = kwargs["node_data"]
    node = get_better_node(node_data, current=status.get("assignedNodeName", None))
    if node:
        logging.info(f"Will assign {name} to {node} due to foip {reason}")
        await assign_node(name, node, memo.change_lock)
