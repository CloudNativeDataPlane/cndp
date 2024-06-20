..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2021-2023 Intel Corporation.

.. _integration-k8s-dp:

Integration of the CNDP app with the AF_XDP plugins for k8s
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Location of the code
--------------------

The source code for the AF_XDP plugins for k8s is located at https://github.com/intel/afxdp-plugins-for-kubernetes


Build Instructions
------------------

In order to build the plugin and deploy it, clone the repo, navigate to the top level directory and run:

.. code-block:: console

	make deploy


Create the config files
-----------------------

* Create the config for the device plugin
    * An example of the device plugin configuration is located at test/e2e/config.json.
    * When deploying the device plugin as a daemonset, the device plugin config is specified as a ``ConfigMap`` in the file deployments/daemonset.yaml.
    * By default, the device plugin creates pools (group of device(s)) of the form ``cndp/i40e`` and ``cndp/E810``. If you want to use this default config, you can request this resource in the pod spec and network attachment definition.
    * Alternately, you can create your own pools (resource types). The name of the pool should be changed to the name of your pool of devices - for example: ``pool1``
    * The device plugin can be configured to use interfaces on your system. The names of the interfaces can be specified in ``devices`` under each pool in ``pools``.
    * Instead of mentioning the interfaces, you could also specify the drivers. In this case, the device plugin discovers the devices on the system that matches the driver name specified in ``drivers`` under each pool in ``pools``.

* Create the network attachment definition
    * An example of the network attachment definition is located at examples/network-attachment-definition.yaml
    * The name of the network attachment definition is specified as the value of ``name`` under ``metadata``.
    * The name of the resource is specified as the value of ``k8s.v1.cni.cncf.io/resourceName`` in the ``annotations`` section under ``metadata``.
        * The resource name is of the form ``cndp/<pool_name>``. The ``cndp/`` part is from the device plugin. The ``<pool_name>`` is from the config.json. For example, ``cndp/pool1``
    * The ``type`` in the ``spec`` - ``config`` section is the name of the CNI.

* Create the pod spec
    * An example of the pod spec is located at examples/pod-spec.yaml
    * In the ``metadata`` section, under ``annotations`` - mention the name of the network attachment as the value of ``k8s.v1.cni.cncf.io/networks``.
    * The ``resources`` in the ``spec`` - ``containers`` section requests the resource mentioned in the network
      attachment definition.

Running the code
----------------

Once the device plugin is deployed as a daemonset, verify that the device plugin pod is running:

.. code-block:: console

   kubectl get pods -n kube-system

The device plugin logs can be viewed at the location specified in the config.json section of the file
deployments/daemonset.yaml for ``logFile``.

.. code-block:: console

  cat /var/log/cndp/cndp/cndp-dp.log

.. note::

   The network attachment definition and pod spec below request a resource named cndp/pool1. The device plugin
   config would need to specify a pool called pool1 with at least one device. If not, you may run into a pod
   failed scheduling warning: 1 insufficient cndp/pool1.

From the top level directory of the CNDP repo, create the network attachment definition

.. code-block:: console

    kubectl create -f containerization/k8s/networks/cndp-cni-nad.yaml

Create the CNDP pod

.. code-block:: console

    kubectl create -f containerization/k8s/cndp-pods/cndp-0-0.yaml
