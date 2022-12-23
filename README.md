# StackGuardian Private Runner v1.0

## Table of Contents

* [1.0 Introduction](#10-introduction)
* [2.0 How it works](#20-how-it-works)
* [3.0 Setup](#30-setup)
  * [3.1 Registration](#31-registration)
    * [3.1.1 Get credentials from StackGuardian](#311-get-credentials-from-stackguardian)
    * [3.1.2 Run the script for registration](#312-run-the-script-for-registration)
  * [3.2 De-registration](#31-de-registration)

## 1.0 Introduction

**StackGuardian Private Runner** represents infrastructure that supports
registering external (self-hosted) instances to the StackGuradian platform.
Configuration is very simple, get credentials from StackGuradian platform,
and run `main.sh` script with credentials.

Check [Setup](#setup) for more details.

## 2.0 How it works

When instance is successfully registered, it is added as *External Instance* to
*AWS Elastic Cluster Service (ECS)*, and it represents customer **Node**.
**Node** is further used for running *ECS tasks*, like docker images.
Each requested *task run* is placed on the **Node**.
Which means, anything described inside that task will be running on **Node** (self-hosted/external instance).
Only, *task definition* will live on *AWS ECS*.

## 3.0 Setup

Setup is very simple. We tried to make it as automated as possible.
All you have to do is run `main.sh` with wanted  option that you want to execute:
[Registration](#registration) or [De-registration](#de-registration), and
provided credentials from *StackGuardian* platform.

> For more details  the `main.sh` script has integrated *help* menu:
> ```
> main.sh --help
> ```

Each option has two **required** arguments:
```
--sg-node-token
--sg-node-api-endpoint
```

We will explain each option in detail below.

### 3.1 Registration

> Registration is more complex part, but it is packed to be as simple as possible
on the surface.

Registration can be done in a few steps described below:

#### 3.1.1  Get credentials from StackGuardian

#### 3.1.2  Run the script for registration

After getting credentials, run script like below while providing
`SG_NODE_TOKEN` and `SG_NODE_API_ENDPOINT`:
```
main.sh register --sg-node-token ${SG_NODE_TOKEN} --sg-node-api-endpoint ${SG_NODE_API_ENDPOINT}
```

### 3.2 De-registration

De-registration is run almost the same way as registration:

```
main.sh deregister --sg-node-token ${SG_NODE_TOKEN} --sg-node-api-endpoint ${SG_NODE_API_ENDPOINT}
```
