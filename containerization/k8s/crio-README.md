# CNDP with CRI-O Container Runtime

Kubernetes expects a Container Runtime to implement its Container Runtime
Interface (CRI). The CRI-O runtime is built specifically for this purpose. It is
a lightweight alternative to containerd. For more information, refer to the
[CRI-O website](https://cri-o.io/). To build containers, this document uses
[podman](https://podman.io/).

## References

The information in this document is sourced from the Kubernetes documentation.

- [Container-runtimes](https://kubernetes.io/docs/setup/production-environment/container-runtimes/)
- [Install kubeadm](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/)

## Install CRI and Kubernetes

This document assumes a fresh install of Ubuntu 21.04 as the base OS where
Kubernetes runs. It describes one way to setup a single node cluster to test and
develop applications.

### Install packages

Install some required packages.

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl
```

### Configure CRI-O pre-requisites

Create the .conf file to load the modules at boot up.

```bash
cat <<EOF | sudo tee /etc/modules-load.d/crio.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter
```

Setup required sysctl params. These persist across reboots.

```bash
cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
net.bridge.bridge-nf-call-iptables  = 1
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

sudo sysctl --system
```

Configure a proxy (if necessary).

```bash
export http_proxy="http://host:port"
export https_proxy="http://host:port"
export no_proxy=<HOST IP>,<HOST NAME>,localhost,127.0.0.1

sudo mkdir -p /etc/systemd/system/crio.service.d

cat <<EOF | sudo tee /etc/systemd/system/crio.service.d/proxy.conf >/dev/null
[Service]
Environment="HTTP_PROXY=$http_proxy"
Environment="HTTPS_PROXY=$https_proxy"
Environment="NO_PROXY=$no_proxy,10.96.0.0/12,10.244.0.0/16"
EOF
```

Increase locked memory limit so containers have enough memory for packet
buffers.

```bash
cat <<EOF | sudo tee /etc/systemd/system/crio.service.d/limits.conf >/dev/null
[Service]
LimitMEMLOCK=infinity
EOF
```

### Install CRI-O

Set environment variables for the host OS and the CRI-O version. The CRI-O
version must match the version of Kubernetes that is installed.

```bash
export OS=xUbuntu_21.04
export VERSION=1.22
```

Setup repos and keys.
<!-- markdownlint-disable MD013  -->

```bash
curl -fsSL https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/Release.key |
 sudo tee /usr/share/keyrings/libcontainers.asc >/dev/null

curl -fsSL https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:$VERSION/$OS/Release.key |
 sudo tee /usr/share/keyrings/libcontainers-cri-o.asc >/dev/null

cat <<EOF | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
deb [signed-by=/usr/share/keyrings/libcontainers.asc] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/ /
EOF

cat <<EOF | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:$VERSION.list
deb [signed-by=/usr/share/keyrings/libcontainers-cri-o.asc] http://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/ /
EOF
```

<!-- markdownlint-enable MD013  -->

Install CRI-O.

```bash
sudo apt-get update
sudo apt-get install -y cri-o cri-o-runc
```

Update where CRI-O looks for CNI plugins (required for Multus CNI).

```bash
cat <<EOF | sudo tee /etc/crio/crio.conf.d/10-crio-cni.conf >/dev/null
[crio.network]
plugin_dirs = ["/usr/libexec/cni"]
EOF
```

Enable CRI-O.

```bash
sudo systemctl daemon-reload
sudo systemctl enable crio --now
```

### Install Kubernetes

Setup repos and keys.

```bash
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg |
 sudo tee /usr/share/keyrings/kubernetes-archive-keyring.gpg >/dev/null

cat <<EOF | sudo tee /etc/apt/sources.list.d/kubernetes.list
deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main
EOF
```

Check which versions of Kubernetes are available. Install one that matches the
CRI-O version.

```bash
sudo apt-get update
sudo apt-cache madison kubelet | grep $VERSION
```

Install a compatible Kubernetes version.

```bash
sudo apt-get install -y kubelet=1.22.7-00 kubeadm=1.22.7-00 kubectl=1.22.7-00
sudo apt-mark hold kubelet kubeadm kubectl
```

### Create a cluster

Disable swap (required by Kubernetes).

```bash
sudo swapoff -a
```

Reserve hugepages (not required, but recommended).

```bash
cat <<EOF | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages >/dev/null
256
EOF
```

Create a cluster.

```bash
sudo kubeadm init --v 99 --pod-network-cidr=10.244.0.0/16 --ignore-preflight-errors=all
```

Configure access to the cluster.

```bash
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

### Install CNI

Deploy Flannel and Multus.

```bash
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset-crio.yml
```

### Install AF_XDP Device Plugin

Download the deployment file.

```bash
curl -fsSLo afxdp-daemonset.yml https://raw.githubusercontent.com/intel/afxdp-plugins-for-kubernetes/master/deployments/daemonset.yml
```

Edit the pool configuration to suit the environment.

```json
data:
  config.json: |
    {
        ... snipped ...
        "pools": [
            {
                "name": "pool1",
                "drivers": ["i40e"]
            }
        ]
    }
```

Deploy the device plugin.

```bash
kubectl create -f afxdp-daemonset.yml
```

Verify the device-plugin is running.

```bash
kubectl get pods -n kube-system
```

### Build CNDP container

Install podman.

```bash
sudo apt-get install -y podman
```

Build the CNDP container. The docker.io prefix is used so the pod-spec can
reference "image: cndp" instead of "image: localhost/cndp".

```bash
sudo -E podman build -t docker.io/cndp --format docker -f containerization/docker/ubuntu/Dockerfile .
```

### Deploy CNDP pod

Create network attachment definition.

```bash
kubectl create -f containerization/k8s/networks/cndp-cni-nad.yaml
```

Allow CNDP pods to be scheduled on the control-plane node.

```bash
kubectl taint nodes --all node-role.kubernetes.io/master-
kubectl label node NAME <HOST >cndp="true"
```

Deploy the CNDP pod.

```bash
kubectl create -f containerization/k8s/cndp-pods/cndp-0-0.yaml
```
