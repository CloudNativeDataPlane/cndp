# Docker Setup

## Step 1: Docker Installation

Add the docker repo:

```bash
sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl \
   software-properties-common gnupg2
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) \
  stable"
```

Install docker-ce:

```bash
sudo apt-get install -y docker-ce docker-ce-cli
```

Ensure that the overlay driver is what's used for docker-ce and memlock limit is
removed:

```bash
cat <<EOF | sudo tee /etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2",
  "default-ulimits": {
    "memlock": {
      "Name": "memlock",
      "Hard": -1,
      "Soft": -1
   }
  }
}
EOF
```

For more info, please follow the following instructions :

1. [Ubuntu](https://docs.docker.com/install/linux/docker-ce/ubuntu/)
1. [Fedora](https://docs.docker.com/install/linux/docker-ce/fedora/)
1. [CentOS](https://docs.docker.com/install/linux/docker-ce/centos/)

> **Note:** Only Ubuntu 21.04 is tested with the included Dockerfile.

## Step 2: Docker Proxy Configuration

If you are behind an HTTP or HTTPS proxy server, you will need to add this
configuration in the Docker systemd service file.

- Create a systemd drop-in directory for the docker service:

```cmd
sudo mkdir -p /etc/systemd/system/docker.service.d
```

- Create a file called /etc/systemd/system/docker.service.d/http-proxy.conf that
  adds the HTTP_PROXY environment variable:

```bash
[Service]
Environment="HTTP_PROXY=http://proxy.example.com:80/"
```

Or, if you are behind an HTTPS proxy server, create a file called
/etc/systemd/system/docker.service.d/https-proxy.conf that adds the HTTPS_PROXY
environment variable:

```bash
[Service]
Environment="HTTP_PROXY=http://proxy.example.com:80/"
```

Or create a single file with all the proxy configurations:
/etc/systemd/system/docker.service.d/proxy.conf

```bash
[Service]
Environment="HTTP_PROXY=http://proxy.example.com:80/"
Environment="HTTPS_PROXY=http://proxy.example.com:80/"
Environment="NO_PROXY=localhost"
```

- Flush changes:

```cmd
sudo systemctl daemon-reload
```

- Restart Docker:

```cmd
sudo systemctl restart docker
```

- Check docker environment variables:

```cmd
sudo systemctl show --property=Environment docker
```

## Step 3: Add user to docker group

This step is required to run docker commands as a non-root user.

```cmd
sudo usermod -aG docker $USER
newgrp docker
```

The `newgrp` command activates the group changes immediately. Without it you
must logout and login again for new groups to take effect.

## Step 4: Testing Docker Installation

```cmd
docker run hello-world
```

The output should be something like:

```bash
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
5b0f327be733: Pull complete
Digest: sha256:07d5f7800dfe37b8c2196c7b1c524c33808ce2e0f74e7aa00e603295ca9a0972
Status: Downloaded newer image for hello-world:latest
Hello from Docker!
This message shows that your installation appears to be working correctly.
To generate this message, Docker took the following steps:
1. The Docker client contacted the Docker daemon.
2. The Docker daemon pulled the "hello-world" image from the Docker Hub.
3. The Docker daemon created a new container from that image which runs the
executable that produces the output you are currently reading.
4. The Docker daemon streamed that output to the Docker client, which sent it
to your terminal.
```

## Step 5: Build the cndp container

> **Note:** Follow INSTALL.md in the CNDP top level directory if CNDP
> dependencies are not installed

To build the container image using `docker` from the top level CNDP directory
call:

```cmd
make oci-image
```

To build the container image using `buildah` from the top level CNDP directory
call:

```cmd
make Builder=buildah oci-image
```

To run the container Ubuntu image using `docker` from the top level CNDP
directory call:

```cmd
make ce-run
```

To run the container Ubuntu image using `podman` from the top level CNDP
directory call:

```cmd
make CE=podman ce-run
```

To run the container Fedora image using `docker` from the top level CNDP
directory call:

```cmd
make ce-fed-run
```

To run the container Fedora image using `podman` from the top level CNDP
directory call:

```cmd
make CE=podman ce-fed-run
```

## Step 6: Run the cndp docker container

From the top level CNDP directory call:

```cmd
make docker-run
```
