# netcup failover-IP operator

This operator monitors node objects and assigns netcup failover IPs to one of the
"healthiest" nodes. This can be used as a "poor man's load balancer" for the control
plane or services on a k8s cluster running in netcup. The operator also ensures that
your nodes are configured to receive traffic for your failover IP(s)!

Built in Python 🐍, using the [Kubernetes Operator Framework (kopf)](https://github.com/nolar/kopf),
[cloudcoil](https://cloudcoil.github.io/cloudcoil/) and
[pyroute2](https://github.com/svinota/pyroute2).

## Motivation

I wanted a single point of contact for a cluster I'm hosting in netcup, but didn't want
to add additional nodes for "real" load balancers. As of writing, netcup does not offer
managed load balancers (2025). My solution is to automatically assign a failover ip to
one of the "healthiest" nodes. This solves two problems:

1) It allows me to perform maintenance on individual nodes, without having to pay
   too much attention to networking

2) It recovers connectivity for the cluster if the currently serving node becomes
   unhealthy / dies

## Limitations

Especially for Problem 2) this approach is **not** the best solution, since the
failover will only happen once the control-plane detected that the node is unhealthy or
was lost, which may happen instantly or take a few minutes. Furthermore, rerouting the
failover-ip also takes a few seconds.

Another important consideration is that netcup failover ips can only be re-assigned
**every 5 Minutes**!

## Architecture / Details

Technically speaking, there are two operators: The *foip* operator and the
*node_interface* operator. They run as two containers in a daemonSet.

### The foip operator ...

... monitors nodes and failoverIPs (foips) and makes sure that the foips are assigned 
to one of the "healthiest" nodes. If there is an issue with the node that currently
has a foip assigned, it will try to immediately reroute the foip to a healthier node.
If that fails because of timeouts from netcup (foips may only be re-routed every 
5 minutes) or because credentials are missing / incorrect, it will try again every 30
seconds. The credentials and parameters for netcups API are taken from secrets and 
annotations on the nodes (see [Preparation](#preparation)).

While there is an instance of this controller on any node where the daemonSet is
scheduled, there is only one active instance to prevent race-conditions. They 
synchronize via [kopf-peerings](https://kopf.readthedocs.io/en/stable/peering/). 
If the node running the active instance dies, another instance will take over.

### The node_interface operator

Because there is only one active instance of the foip operator at a given time, a
second operator is needed to make sure the nodes network interfaces are configured
to receive traffic from the foips.

**That's right, you don't have to handle network configuration of your nodes! 🥳**

Every instance of the  node_interface operator checks on what node it is 
running on and then retrieves that node's `netcup.noshoes.xyz/primary-mac` annotation.
It looks for an interface with that mac address and will ensure that all failover ips
are assigned to that interface. This way, the node can start picking up traffic as soon
as rerouting happened on netcup's infrastructure.

### Choosing the healthiest node

For choosing the "healthiest" node, the operator exclusively checks information in the
control-plane. Several "issues" are checked for, and then the node(s) with the least
severe issues are chosen to handle traffic from the foip.

The issues from most- to least-severe are:

```    
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
```

Examples:

If all Nodes have PID pressure but one is additionally marked unschedulable, we will
take one of the nodes with PID pressure.

If all other nodes are not ready, we would choose a node that is marked as unschedulable.

If there is exactly one node with none of these issues, we will assign the foips to it.

## Project status / maturity

This project mostly came to be because I wanted to write a K8s operator for the
learning experience. I had the above described problem to solve and took the
opportunity.

It's "works for the author"-grade software. I am happy to review PRs that improve
it or add flexibility, as long as it doesn't break my use-case. I might also react to
issues, but no promises.

## Usage / Installation

### Preparation

#### Node annotations

The netcup API (also called SCP webservice) needs the vServer id and mac address of the 
primary interface to reroute failover IPs. You can find this information on netcup's
[server control panel](http://servercontrolpanel.de/) under "network". It needs to be 
added to your node objects' annotations (`kubectl edit node <nodename>`): 

```yaml
metadata:
  annotations:
    netcup.noshoes.xyz/primary-mac: 01:02:03:04:05:06
    netcup.noshoes.xyz/server-name: v0123456789123456789
```

Unless both annotations are present, the foip operator will not consider these nodes for
assignment.

#### Allowing the operator to access the netcup api

Activate the
[SCP Webservice](https://helpcenter.netcup.com/en/wiki/server/scp-webservice/) by
creating a password for it. In the namespace where you wish to deploy the operator,
create a secret that contains the username and webservice password for the netcup api.
Note: The SCP **webservice** password is different from the normal SCP password you use
on the SCP web-interface!

```sh
kubectl create secret generic netcup-webservice-credentials \ 
--from-literal=loginName=123456 
--from-literal=password=... # Your password
```

### Installing the chart

The chart is published on the github oci registry as:
`oci://ghcr.io/niklasbeierl/netcup-foip-operator`

You can get the default values via:

`helm show values oci://ghcr.io/niklasbeierl/netcup-foip-operator:0.2.0`

(Note the version!)

You can customize the values to your liking, and even already specify your failover ips
in there (see next step). But you can also install it with defaults and it should work.

`helm install netcup-foip oci://ghcr.io/niklasbeierl/netcup-foip-operator:0.2.0`

### Adding failover IPs

The chart installs a custom resource into your cluster called *failoverip* - *foip*
for short. It contains the actual ip to assign and the name of the secret to use for
communicating with the netcup api. Create such a resource and if all is right it should
get assigned within a few seconds.

```yaml
kind: FailoverIp
metadata:
  name: myfailoverip
spec:
  ip: a.b.c.d
  # make sure to reference the secret correctly
  # the FailoverIp and secret need to be in the same namespace as the chart installation
  secretName: netcup-failover-credentials
```

### Checking the status of your failover IP

The operator will populate the `status` field of the failoverip crd:

```sh
M ~/c/p/netcup-foip-operator kubectl describe foip                                                                                    main ✱
Name:         myfailoverip

...                
 
Spec:
  Ip:           1.1.1.1
  Secret Name:  netcup-webservice-credentials
Status:
  Assigned Node:      node-1
  Desired Node:       node-1
  Last Sync Attempt:  2025-08-09T19:36:29Z
  Last Sync Success:  2025-08-09T19:36:30Z

```

## Troubleshooting

#### logs

The first thing to check if the operator isn't acting as expected are the logs. To
get them from all containers run:

```sh
kubectl logs -l app.kubernetes.io/name=netcup-foip-operator -f --prefix \ 
--all-containers --max-log-requests 6
```

`max-log-requests` will generally need to be 2x the number of your nodes.

#### Accessing LoadBalancer services on the failover ip

If you want to access LoadBalancer services that are exposed through klipper/ServiceLB,
with the failoverIP (likely the case if you are running K3s), you need to let ServiceLB
know about this, by adding:

```yaml
externalIPs:
  - a.b.c.d # Your failoverIP 
```

to the services `spec`. Other "Bare Metal" load balancers might have similar
requirements.

