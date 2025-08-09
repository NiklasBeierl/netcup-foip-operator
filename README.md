# Netcup failover-IP operator

This operator monitors node objects and assigns netcup failover IPs to on of the 
"healthiest" nodes. This can be used as a "poor man's load balancer" for the control 
plane or services on a k8s cluster running in netcup.

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

The netcup SOAP API needs the vServer id and mac address of the primary interface to
reroute failover IPs. You can find this information on netcup's [server control panel]
(http://servercontrolpanel.de/) and it needs to be added to your node objects'
annotations (`kubectl edit node <nodename>`):

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

TODO

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

## Troubleshooting

#### logs

The first thing to check if the operator isn't acting as expected are the logs. To
get them from all containers run:

```sh
k logs -l app.kubernetes.io/name=netcup-foip-operator -f --prefix --all-containers --max-log-requests 6
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

to the services `spec`.

Other "Bare Metal" load balancers might have similar requirements.

