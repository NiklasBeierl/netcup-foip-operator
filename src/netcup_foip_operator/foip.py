import logging
import os
import random
from asyncio import Lock
from base64 import b64decode
from datetime import UTC, datetime
from hashlib import sha256

import kopf
from cloudcoil.errors import ResourceNotFound
from cloudcoil.models.kubernetes.core.v1 import Node, Secret
from zeep import Client
from zeep.exceptions import Error as ZeepError

from netcup_foip_operator import MAC_ANNOT, NODE_ANNOTATIONS, SERVERNAME_ANNOT
from netcup_foip_operator.models.v1 import FailoverIp, FailoverIpStatus

SOAP_ADDR = "https://www.servercontrolpanel.de/WSEndUser?wsdl"


def timestamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@kopf.on.startup()
async def configure(memo: kopf.Memo, settings: kopf.OperatorSettings, **_):
    settings.posting.enabled = False

    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix="netcup.noshoes.xyz",
        key="last-handled-foip",
    )
    settings.persistence.finalizer = "netcup.noshoes.xyz/foip"

    # Peering to ensure only one instance is running
    settings.peering.clusterwide = True
    settings.peering.mandatory = True
    settings.peering.name = "netcup-failover-ip"
    if prio_src := os.environ.get("PEERING_PRIO"):
        sha = sha256(prio_src.encode())
        settings.peering.priority = int.from_bytes(sha.digest(), "big")
    else:
        # Best effort: Use a random number
        settings.peering.priority = random.randint(0, 2**16)


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
    # Coroutine raised StopIteration??
    # field=["spec.unschedulable", "name", "status.conditions"],
    annotations=NODE_ANNOTATIONS,
)
async def node_issues(name, status, spec, **_):
    """Index that tracks issues of nodes."""
    data = {
        "name": name,
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
    """
    Choose "the best" or a "better" node than the current one.

    If the current one is as good as it gets, return None.
    """
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
async def failover_ips_by_node(name: str | None, status: kopf.Status, **_):
    """Tracks what failover ips are assigned to what nodes."""
    return {status.get("desiredNode"): name}


# We don't resume on nodes. We resume on foips instead
@kopf.on.create("node", annotations=NODE_ANNOTATIONS)
@kopf.on.update(
    "node",
    field=[
        "status.conditions",
        f"annotations.{MAC_ANNOT}",
        f"annotations.{SERVERNAME_ANNOT}",
        "spec.unschedulable",
    ],
    annotations=NODE_ANNOTATIONS,
)
@kopf.on.delete("node", annotations=NODE_ANNOTATIONS)
async def node(
    memo: kopf.Memo,
    reason: str,
    name: str | None,
    **kwargs,
):
    assert name is not None

    node_issues: kopf.Index = kwargs["node_issues"]
    failover_ips_by_node: kopf.Index = kwargs["failover_ips_by_node"]

    # We store assignments and execute them later to avoid changing the indices while
    # iterating them (which leads to a runtime error).
    assignments = {}
    for node_name, foips in failover_ips_by_node.items():
        for ip in foips:
            current = node_name

            if reason == "delete" and node_name == name:
                current = None

            better_node = get_better_node(node_issues, current=current)
            if better_node is not None:
                logging.info(f"Will assign {ip} to {better_node} due to node {reason}")
                assignments[ip] = better_node

    if assignments:
        async with memo.change_lock:
            for ip, better_node in assignments.items():
                await assign_node(ip, better_node)


async def assign_node(ip_name: str, node_name: str):
    """
    Updating the custom resource and reroute the ip through the netcup api.

    On the foip resource, spec.desiredNode is updated as soon as the node is deemed
    fit for it. If the secret is not found / malformed or something goes wrong
    when invoking the netcup API, we raise a PermanentError. The timer will later
    detect a mismatch between desired and assigned node and retry the assignment.
    """
    failover_ip = FailoverIp.get(name=ip_name)
    if failover_ip is None:
        raise kopf.PermanentError(f"Failover ip {ip_name} not found.")

    # "new" foips have no status field yet
    if failover_ip.status is None:
        failover_ip.status = FailoverIpStatus()

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

    # At this point we know the Node is suitable to get the ip assigned, so we update
    # the resource
    failover_ip.status.desired_node = node_name
    failover_ip = await failover_ip.async_update()
    assert failover_ip.status is not None

    secret_name = failover_ip.spec.secret_name

    try:
        secret = Secret.get(name=secret_name)
    except ResourceNotFound as e:
        raise kopf.PermanentError(
            f"Secret {secret_name} for failover ip {ip_name} not found."
        ) from e

    if secret.data is None:
        raise kopf.PermanentError(f"Secret {secret_name} has no data.")
    try:
        login_name = b64decode(secret.data["loginName"]).decode()
        password = b64decode(secret.data["password"]).decode()
    except KeyError as e:
        raise kopf.PermanentError(f"secret {secret_name} has no .data.{e.args[0]}")

    # We will now attempt to talk to the API
    failover_ip.status.last_sync_attempt = timestamp()
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

    ip = failover_ip.spec.ip

    if ip in result:
        logging.warn(f"{ip} already assigned to {node_name} in netcup")
        failover_ip.status.assigned_node = node_name
        failover_ip.status.last_sync_success = timestamp()
        await failover_ip.async_update()
        return

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
    except ZeepError as e:
        raise kopf.PermanentError(
            f"Failed to reassign failover ip {ip_name}: {e.message} "
            "This will be reattempted later."
        ) from e


# TODO: Unassign foip if resource is deleted...
# @kopf.on.delete("failoverip.netcup.noshoes.xyz")
@kopf.on.resume("failoverip.netcup.noshoes.xyz")
@kopf.on.create("failoverip.netcup.noshoes.xyz")
@kopf.on.update("failoverip.netcup.noshoes.xyz", field="spec")
async def foip(
    reason: str, memo: kopf.Memo, name: str | None, status: kopf.Status, **kwargs
):
    # TODO: Add ip address to interface through pyroute
    assert name is not None

    node_issues: kopf.Index = kwargs["node_issues"]

    # Fixing up discrepancies between desired and assigned is the timers job
    current_node = status.get("desiredNode", None)
    better_node = get_better_node(node_issues, current=current_node)
    if better_node:
        logging.info(f"Will assign {name} to {better_node} due to foip {reason}")
        async with memo.change_lock:
            await assign_node(name, better_node)


@kopf.timer("failoverip.netcup.noshoes.xyz", retries=1, interval=30)
async def foip_timer(name: str | None, memo: kopf.Memo, status: kopf.Status, **_):
    assert name is not None

    # No desired node yet, this will change through the foip or node handlers
    if not (desired := status.get("desiredNode")):
        return

    assigned = status.get("assignedNode")

    if desired != assigned:
        logging.info(
            f"Will assign {name} to {desired} because it is still assigned to {assigned}"
        )
        async with memo.change_lock:
            await assign_node(name, desired)
