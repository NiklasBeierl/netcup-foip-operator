import logging
import os
import random
from asyncio import Lock
from base64 import b64decode
from datetime import UTC, datetime

import kopf
from cloudcoil.models.kubernetes.core.v1 import Node, Secret
from zeep import Client
from zeep.exceptions import Error as ZeepError
from zeep.exceptions import Fault

from netcup_foip_controller.models.v1 import FailoverIp, FailoverIpStatus

SOAP_ADDR = "https://www.servercontrolpanel.de/WSEndUser?wsdl"
MAC_ANNOT = "netcup.noshoes.xyz/primary-mac"
SERVERNAME_ANNOT = "netcup.noshoes.xyz/server-name"

# Nodes to consider for failover ips need to have these annotations
NODE_ANNOTATIONS = {
    MAC_ANNOT: kopf.PRESENT,
    SERVERNAME_ANNOT: kopf.PRESENT,
}


def timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@kopf.on.startup()
async def configure(memo: kopf.Memo, settings: kopf.OperatorSettings, **_):
    # Peering to ensure only one instance is running
    settings.peering.name = "netcup-failover-ip"
    if prio_src := os.environ.get("PEERING_PRIO"):
        settings.peering.priority = int.from_bytes(prio_src.encode("utf-8"), "big")
    else:
        # Best effort: Use a random number
        settings.peering.priority = random.randint(0, 2**16)

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

# When choosing the node, we sort them by their issues and ...
SORTING = ISSUES + (
    "name",  # ... use the name as tie-breaker
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
    return {status.get("desiredNode"): name}


# We don't "resume" on nodes. We resume on foips instead...
@kopf.on.create("node", annotations=NODE_ANNOTATIONS)
@kopf.on.update(
    "node",
    field="status.conditions",
    annotations=NODE_ANNOTATIONS,
)
@kopf.on.update(
    "node",
    field="spec.unschedulable",
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

    assignments = {}
    for node_name, foips in failover_ips_by_node.items():
        for ip in foips:
            current = node_name

            if reason == "delete" and node_name == name:
                current = None

            better_node = get_better_node(node_data, current=current)
            if better_node is not None:
                logging.info(f"Will assign {ip} to {better_node} due to node {reason}")
                assignments[ip] = better_node

    async with memo.change_lock:
        for ip, better_node in assignments.items():
            await assign_node(ip, better_node)


async def assign_node(ip_name: str, node_name: str):
    failover_ip = FailoverIp.get(name=ip_name)
    if failover_ip is None:
        raise kopf.PermanentError(f"Failover ip {ip_name} not found.")

    if failover_ip.status is None:
        failover_ip.status = FailoverIpStatus()

    secret_name = failover_ip.spec.secret_name
    secret = Secret.get(name=secret_name)

    # In case of issues with the secret, we just retry after the default delay
    if secret is None:
        raise kopf.TemporaryError(
            f"Secret {secret_name} for failover ip {ip_name} not found."
        )
    if secret.data is None:
        raise kopf.TemporaryError(f"Secret {secret_name} has no data.")
    try:
        login_name = b64decode(secret.data["loginName"]).decode()
        password = b64decode(secret.data["password"]).decode()
    except KeyError as e:
        raise kopf.TemporaryError(f"secret {secret_name} has no .data.{e.args[0]}")

    # In case of issues with the node we abort, since we watch for updates on nodes
    node = Node.get(name=node_name)
    if node is None:
        raise kopf.PermanentError(f"Node {node_name} not found.")
    if node.metadata is None or node.metadata.annotations is None:
        raise kopf.PermanentError(f"Node {node_name} seems to have no annotations.")
    try:
        mac = node.metadata.annotations[MAC_ANNOT]
        vserver_name = node.metadata.annotations[SERVERNAME_ANNOT]
    except KeyError as e:
        raise kopf.PermanentError(f"Node {node_name} has no annotation {e.args[0]}")

    ip = failover_ip.spec.ip

    failover_ip.status.desired_node = node_name
    failover_ip = await failover_ip.async_update()
    assert failover_ip.status is not None

    try:
        client = Client(SOAP_ADDR)
        result = client.service.getVServerIPs(
            loginName=login_name,
            password=password,
            vserverName=vserver_name,
        )
    except ZeepError as e:
        raise kopf.PermanentError("Failed to get vserver IPs") from e

    if ip in result:
        logging.warn(f"{ip} already assigned to {node_name} in netcup")
        failover_ip.status.assigned_node = node_name
        failover_ip.status.last_sync_success = timestamp()
        await failover_ip.async_update()
        return

    failover_ip.status.last_sync_attempt = timestamp()
    failover_ip = await failover_ip.async_update()
    assert failover_ip.status is not None

    try:
        client.service.changeIPRouting(
            loginName=login_name,
            password=password,
            routedIP=ip,
            routedMask=32,
            destinationVserverName=vserver_name,
            destinationInterfaceMAC=mac,
        )
        logging.info(f"Assigned {ip_name} to {node_name} in netcup")
        failover_ip.status.assigned_node = node_name
        failover_ip.status.last_sync_success = timestamp()
        await failover_ip.async_update()
    except Fault as e:
        raise kopf.PermanentError(
            f"Failed to reassign failover ip {ip_name}: {e.message} "
            "This will be reattempted later."
        )


# TODO: Unassign foip if resource is deleted...
# @kopf.on.delete("failoverip.netcup.noshoes.xyz")
@kopf.on.resume("failoverip.netcup.noshoes.xyz")
@kopf.on.create("failoverip.netcup.noshoes.xyz")
@kopf.on.update("failoverip.netcup.noshoes.xyz", field="spec")
async def foip(
    reason: str, memo: kopf.Memo, name: str | None, status: kopf.Status, **kwargs
):
    assert name is not None

    node_data: kopf.Index = kwargs["node_data"]

    # Fixing up discrepancies between desired and assigned is the timers job
    current_node = status.get("desiredNode", None)
    better_node = get_better_node(node_data, current=current_node)
    if better_node:
        logging.info(f"Will assign {name} to {better_node} due to foip {reason}")
        async with memo.change_lock:
            await assign_node(name, better_node)


@kopf.timer("failoverip.netcup.noshoes.xyz", interval=30)
async def foip_timer(name: str | None, memo: kopf.Memo, status: kopf.Status, **_):
    assert name is not None

    if not (desired := status.get("desiredNode")):
        return

    if desired != status.get("assignedNode"):
        logging.info(f"Will assign {name} to {desired} (timer)")
        async with memo.change_lock:
            try:
                await assign_node(name, desired)
            except kopf.TemporaryError as e:
                # Retries are done through the timer interval
                raise kopf.PermanentError(
                    f"Timer failed to assign {name} to {desired}"
                ) from e
