# CNDP Kubernetes Reference Logging Architecture

CNDP provides a reference logging architecture based on Fluent Bit combined with the Elasticsearch
output plugin. Kibana provides a user interface to visualize the data stored in the Elasticsearch
database.

This guide describes a procedure to deploy the logging stack and configure Kibana to view the logs.

# Deploy logging stack

Use the following procedure to configure and deploy the Elasticsearch, Kibana, and Fluent Bit pods.

## Elasticsearch and Kibana

Create elasticsearch.yaml and kibana.yaml deployment files. Both applications run in the "logging"
namespace and are reachable through a service NodePort.

```
cat <<EOF > elasticsearch.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elasticsearch
  namespace: logging
spec:
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
      - name: elasticsearch
        image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
        env:
        - name: discovery.type
          value: single-node
        ports:
        - containerPort: 9200
          name: http
          protocol: TCP

---

apiVersion: v1
kind: Service
metadata:
  name: elasticsearch
  namespace: logging
  labels:
    service: elasticsearch
spec:
  type: NodePort
  selector:
    app: elasticsearch
  ports:
  - port: 9200
    targetPort: 9200
EOF
```

```
cat <<EOF > kibana.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kibana
  namespace: logging
spec:
  selector:
    matchLabels:
      app: kibana
  template:
    metadata:
      labels:
        app: kibana
    spec:
      containers:
      - name: kibana
        image: docker.elastic.co/kibana/kibana:7.17.0
        env:
        - name: XPACK_SECURITY_ENABLED
          value: "true"
        - name: TELEMETRY_ENABLED
          value: "false"
        ports:
        - containerPort: 5601
          name: http
          protocol: TCP

---

apiVersion: v1
kind: Service
metadata:
  name: kibana
  namespace: logging
  labels:
    service: kibana
spec:
  type: NodePort
  selector:
    app: kibana
  ports:
    - port: 5601
      targetPort: 5601
EOF
```

Create the "logging" namespace and deploy Elasticsearch and Kibana

```
kubectl create namespace logging
kubectl create -f elasticsearch.yaml
kubectl create -f kibana.yaml
```

## Fluent Bit

Fluent Bit needs access to some information about the pods running on its node so it needs a
RoleBinding.

```
kubectl create -f https://raw.githubusercontent.com/fluent/fluent-bit-kubernetes-logging/master/fluent-bit-service-account.yaml
```

On K8s version <1.22 the API is v1beta. Use these if the K8s cluster version is <1.22.

```
kubectl create -f https://raw.githubusercontent.com/fluent/fluent-bit-kubernetes-logging/master/fluent-bit-role.yaml
kubectl create -f https://raw.githubusercontent.com/fluent/fluent-bit-kubernetes-logging/master/fluent-bit-role-binding.yaml
```

On K8s version >=1.22 the API is v1beta. Use these if the K8s cluster version is >=1.22.

```
kubectl create -f https://raw.githubusercontent.com/fluent/fluent-bit-kubernetes-logging/master/fluent-bit-role-1.22.yaml
kubectl create -f https://raw.githubusercontent.com/fluent/fluent-bit-kubernetes-logging/master/fluent-bit-role-binding-1.22.yaml
```

The Fluent Bit DaemonSet is configured using a ConfigMap.

If the CRI used on the cluster is docker, the default configuration can be used.

```
kubectl create -f https://raw.githubusercontent.com/fluent/fluent-bit-kubernetes-logging/master/output/elasticsearch/fluent-bit-configmap.yaml
kubectl create -f https://raw.githubusercontent.com/fluent/fluent-bit-kubernetes-logging/master/output/elasticsearch/fluent-bit-ds.yaml
```

If the CRI used on the cluster is containerd, the default ConfigMap must be modified to change the
Parser from 'docker' to 'cri' and the default DaemonSet must be modified to change the log path from
'/var/lib/docker/containers' to '/var/log/pods'.

```
wget https://raw.githubusercontent.com/fluent/fluent-bit-kubernetes-logging/master/output/elasticsearch/fluent-bit-configmap.yaml
sed -i -r 's/(Parser +)docker/\1cri/g' fluent-bit-configmap.yaml
wget https://raw.githubusercontent.com/fluent/fluent-bit-kubernetes-logging/master/output/elasticsearch/fluent-bit-ds.yaml
sed -i -r 's/\/var\/lib\/docker\/containers/\/var\/log\/pods/g' fluent-bit-ds.yaml
kubectl create -f fluent-bit-configmap.yaml
kubectl create -f fluent-bit-ds.yaml
```

## Check Deployment

Assuming the above steps completed without error and containers were downloaded and started
successfully, run the following commands to check the deployment.

### Check Pods

```
$ kubectl get pods -n logging
NAME                             READY   STATUS    RESTARTS   AGE
elasticsearch-546795648c-r6dhz   1/1     Running   0          35m
fluent-bit-4lb7z                 1/1     Running   0          34m
kibana-b56fc6484-24wc8           1/1     Running   0          35m
```

### Check Services

```
$ kubectl get services -n logging
NAME            TYPE       CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
elasticsearch   NodePort   10.107.119.4    <none>        9200:31816/TCP   35m
kibana          NodePort   10.101.28.159   <none>        5601:32348/TCP   35m
```

To access the Kibana user interface on the node where services are deployed, open a browser and
navigate to localhost:32348. Note the actual port may different than the one displayed here.

If the node does not have a browser, access the Kibana user interface through the node's IP instead
of localhost.

# Configure Kibana

Access the Kibana user interface, navigate to HOST:PORT/app/management/kibana/indexPatterns.

Create an Index Pattern named "logstash-\*" with a Timestamp Field equal to "@timestamp".

Navigate to HOST:PORT/app/discover.

From the "Available Fields" menu, find "Kubernetes.pod\_name" and click the "+" icon to add the
field. Do the same for the "Message" field.

Use the Search bar to filter on "cndp". Deploy the CNDP pod and observe logs from the
cndp-device-plugin and cndp pod.

# References

1. Fluent Bit - https://docs.fluentbit.io/manual/
2. Fluent Bit Kubernetes - https://docs.fluentbit.io/manual/installation/kubernetes
3. Elastic - https://www.elastic.co/guide/index.html
