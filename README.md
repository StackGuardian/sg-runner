# StackGuardian Private Runner v1.0

## Table of Contents

- [1.0 Introduction](#10-introduction)
- [2.0 How it works](#20-how-it-works)
- [3.0 Setup](#30-setup)
  - [3.1 Environment](#31-environment)
  - [3.2 Registration](#32-registration)
    - [3.2.1 Get credentials from StackGuardian](#331-get-credentials-from-stackguardian)
    - [3.2.2 Run the script for registration](#332-run-the-script-for-registration)
  - [3.3 De-registration](#34-de-registration)
  - [3.4 Restart](#34-restart)
- [Other options](#other-options)

## 1.0 Introduction

**StackGuardian Private Runner** represents infrastructure that supports
registering external (self-hosted) instances to the StackGuradian platform.
Configuration is very simple, get credentials from StackGuradian platform,
and run `main.sh` script with credentials.

Check [Setup](#setup) for more details.

## 2.0 How it works

When instance is successfully registered, it is added as _External Instance_ to
_AWS Elastic Cluster Service (ECS)_, and it represents customer **Node**.
**Node** is further used for running _ECS tasks_, like docker images.
Each requested _task run_ is placed on the **Node**.
Which means, anything described inside that task will be running on **Node** (self-hosted/external instance).
Only, _task definition_ will live on _AWS ECS_.

## 3.0 Setup

> **IMPROTANT:**
> To ensure a smooth lifecycle for your instance, it is important to avoid having any IAM Roles attached to it.
> Having IAM Roles attached can potentially cause connection issues and disrupt the instance's functioning.
> Therefore, it is recommended to remove or detach any IAM Roles from the instance to prevent any complications during its lifecycle.
> This precaution will help maintain the stability and uninterrupted operation of the instance.

Setup is very simple. We tried to make it as automated as possible.
All you have to do is run `main.sh` with wanted option that you want to execute:
[Registration](#registration) or [De-registration](#de-registration), and
provided credentials from _StackGuardian_ platform.

> For more details the `main.sh` script has integrated _help_ menu:
>
> ```
> ./main.sh --help
> ```

### 3.1 Environment

There are couple of environment variables that can be overriden for the purposes of testing:

```
SG_BASE_API
LOG_DEBUG
CGROUPSV2_PREVIEW
```

- `SG_BASE_API`: Change base of API. Default: `https://api.app.stackguardian.io/api/v1`
- `LOG_DEBUG`: If set to `true`, print additional `DEBUG` logs
- `CGROUPSV2_PREVIEW`: If set to `true`, enables management of `cgroupsv2`

Environment variables can be exported using `export` or saved to `.env` which is loaded automatically.

### 3.2 Registration

> Registration is more complex part, but it is packed to be as simple as possible
> on the surface.

Registration can be done in a few steps described below:

#### 3.2.1 Get credentials from StackGuardian

#### 3.2.2 Run the script for registration

After getting credentials, run script like below while providing
`SG_NODE_TOKEN`, `ORGANIZATION` and `RUNNER_GROUP`:

```
main.sh register \
    --sg-node-token ${SG_NODE_TOKEN} \
    --organization ${ORGANIZATION} \
    --runner-group ${RUNNER_GROUP}
```

### 3.3 De-registration

De-registration is run almost the same way as registration:

```
main.sh deregister \
    --sg-node-token ${SG_NODE_TOKEN} \
    --organization ${ORGANIZATION} \
    --runner-group ${RUNNER_GROUP}
```

> In case local data is corrupted or API call fails, you can force clean everything.
> This is done by providing `-f` or `--force` while executing `deregister`.
> _Force deregister_ will remove all data related to runner script for fresh start.

### 3.4 Restart

As of now, restart is not nativly supported.
But, to achieve similar experinece it is enough to [`deregister`](#32-de-registration) and then [`register`](#31-registration) again.

> This should fix all troubles if something is not working.

## System diagnostics

We included 2 commands for easier system diagnostics and management.
These should help you keep your system clean and debug in case of errors.

> INFO: Any of following actions keep state in a file at `/tmp/diagnostic.json`.

With any command you can provide `--debug` flag.
With this, you will get more output while running commands.

> INFO: All logs are being kept at `/tmp/sg_runner.log`.

### Health check

Besides `register` and `deregister`, script offers easy health checking:

```
./main.sh status
```

This command will print status of `ecs` and `docker` services.
Also, including all related Docker containers (`ecs-agent`, `fluentbit-agent`).

### System prune

Another useful command is `prune` which can be used like:

```
./main.sh prune
```

This command will execute `docker system prune` for everything that is older than **10 days**.

## Managing `cgroupsv2`

Private runner does not support `cgroupsv2`. Since `cgroupsv2` tend to have problems with `docker`.
There is integrated option to toggle between `v2` and `v1` of `cgroups`.

To disable `cgroupsv2` and revert to `cgroupsv1` there is 2 step process as of now:

```
export CGROUPSV2_PREVIEW=true
```

> Check [Environment](#31-environment) for details

and then

```
./main.sh cgropusv2 disable
```

> Reboot is required after such action.

To revert you can just run:

```
./main.sh cgroupsv2 enable
```

## Troubleshooting

- StackGuardian uses AWS SSM to setup connection between SG control plane and runners, you can diagnose SSM client using `ssm-cli get-diagnostics --output table`

- If the registration was successful but you can't see Ping Status and IP Address for the Runner on StackGuardian Platform inside the Runner Group's -> Runner Instances tab please re-register runner using the following command:
    ```bash
    ./main.sh deregister --sg-node-token "TOKEN" --organization "ORG" --runner-group "RUNNER_GROUP" && \
    rm -rf /var/lib/amazon/ssm/ ~/.aws/credentials && \
    ./main.sh register --sg-node-token "TOKEN" --organization "ORG" --runner-group "RUNNER_GROUP"
    ```
