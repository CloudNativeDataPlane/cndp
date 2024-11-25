# Device Containers Getting Started Guide

This guide will walk you through using a [Development Container](https://containers.dev/)
configured with all the tools needed to build and run CNDP. The Dev
Container setup is compatible with local development in Visual Studio Code
and with GitHub Codespaces for cloud-based workflows.

## Prerequisites

- **VSCode**
- **Docker**
- **VSCode Dev Containers Extension**

> **_NOTE_**: Details of the Dev Container prerequisites can be found
[here](https://code.visualstudio.com/docs/devcontainers/tutorial#_prerequisites).

## Basic Workflow

1. Dev Container Configurations can be found in the `.devcontainer` directory.
   Files are set up with configuration details: the Docker image to use,
   extensions to install, environment variables...
   > **_NOTE_**: The Dev Container configuration provided supports both root
   (not recommended) and non-root (recommended) users.
2. Open project in Container: Open the project folder in VS Code or Github
   workspaces to build and attach the development environment.
3. Development: Work as usual, with access to tools and dependencies defined
   in the container.

The following sections will walk through Step 2 in detail.

### Running in Visual Studio Code

Follow these steps to launch and work with the Dev Container in Visual
Studio Code.

Open the project in Visual Studio Code. A pop up will appear asking to reopen
in project in a Dev Container.
![reopen-in-container](./images/reopen-in-container.png)

If the pop up doesn't appear, the container can be launched by accessing the
Visual Studio Code Command Palette and looking for the:
`Dev Containers: Reopen in Container` option as shown below.

![reopen-in-container](./images/rebuild-container.png)

Visual Studio Code will relaunch inside the Dev Container.

When the container is ready CNDP can be built as usual.

### Running in Github Codespace

Use GitHub Codespaces for cloud-based development with the same Dev Container configuration.

### Running the Tutorials in the Dev Container

1. Navigate to your repository and click the `< >Code` dropdown.
2. In the Codespaces tab, click the ellipsis (...), then select `+ New with Options`:
![codespaces-options](./images/codespaces-options.png)
3. (If needed) Select the Branch, the Dev Container configuration, number of CPUs:
![codespaces-config](./images/codespaces-config.png)
4. Click the Button to `Create codespace`.

When the codespace is available CNDP can be built as usual.
