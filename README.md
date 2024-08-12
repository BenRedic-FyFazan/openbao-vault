# REWRITE THIS! 

 # OpenBao
This Ansible role performs a basic [OpenBao](https://openbao.org/)
installation, including filesystem structure and configuration.

## Preface
This role started out as a fork of the [ansible-community/ansible-vault role](https://github.com/ansible-community/ansible-vault/tree/master) with the intention of adapting it for use with OpenBao and to reduce complexity by removing functionality not needed in our environment. 
Expect severe differences in functionality between this role and the ansible-community/ansible-vault role. 
Additionally, as OpenBao is a fork of Hashicorp vault, some paths, variables and the likes still use Hashicorp Vault naming and path conventions.

Thank you [Brian Shumate](https://github.com/brianshumate) for laying the groundwork!

## Installation
- WIP

## Requirements
Role requirements has not been thoroughly tested at this time, but is confirmed working with:
* Ansible: 2.17.2
* OpenBao: 2.0.0
* Ubuntu
  - 22.04 (Jammy Jellyfish)

## Warning
By default, this role may restart `bao` service when played (when there's a
configuration change, OS Packages installed/updated)

When there's no auto-unseal setup on your cluster, the restart may lead to a
situation where all OpenBao instances will be sealed and your cluster will be
down.

To avoid this situation, the service restart by the playbook can be disabled
by using the `vault_service_restart` role variable.

Setting this `vault_service_restart` to `false` will disable the `bao`
service restart by the playbook. You may have to restart the service manually
to load any new configuration deployed.

## Role Variables

The role defines variables in `defaults/main.yml`:

### `vault_listener_localhost_enable`

 - Set this to true if you enable listen vault on localhost
 - Default value: *false*

### `openbao_privileged_install`

 - Set this to true if you see permission errors when the vault files are
   downloaded and unpacked locally. This issue can show up if the role has
   been downloaded by one user (like root), and the installation is done
   with a different user.
 - Default value: *false*

### `openbao_version`

- Version to install
  - Can be overridden with `VAULT_VERSION` environment variable

- Default value: 2.0.0

### `openbao_pkg`

- package filename
- Default value: `"openbao_{{ openbao_version }}_{{ openbao_os }}_{{ openbao_architecture }}.tar.gz"`

### `openbao_archive_url`

- Package download URL
- Default value: `"https://github.com/openbao/openbao/releases/download/v{{ openbao_version }}/bao_{{ openbao_version }}_Linux_{{ openbao_architecture }}.tar.gz"`
- Override this var if you have your archive hosted internally

### `openbao_bin_path`

- Binary installation path
- Default value: `/usr/local/bin`

### `openbao_config_path`

- Configuration file path
- Default value: `/etc/vault.d`

### `vault_use_config_path`

- Use `"{{ openbao_config_path }}"` to configure openbao instead of `"{{ vault_main_config }}"`
- default vaule: *false*

### `openbao_data_path`

- Data path
- Default value: `/var/vault`

### `openbao_log_path`

- Log path
- Default value: `/var/log/vault`

### `openbao_run_path`

- PID file location
- Default value: `/var/run/openbao`

### `openbao_harden_file_perms`

- Whether this role should disallow OpenBao from writing into config and plugin
  path. This should be enabled to follow [Production Hardening](https://learn.hashicorp.com/tutorials/vault/production-hardening).
- Default value: false

### `openbao_manage_user`

- Should this role manage the openbao user?
- Default value: true

### `openbao_user`

- OS user name
- Default value: openbao

### `openbao_group`

- OS group name
- Default value: bin

### `openbao_groups`

- OS additional groups as in ansibles user module
- Default value: null

### `openbao_manage_group`

- Should this role manage the openbao group?
- Default value: false

### `vault_cluster_name`

- Cluster name label
- Default value: dc1

### `vault_datacenter`

- Datacenter label
- Default value:  dc1

### `vault_ui`

- Enable vault web UI
- Default value:  true

### `vault_service_restart`

- Should the playbook restart OpenBao service when needed
- Default value: true

### `vault_service_reload`

- Should the playbook reload OpenBao service when the main config changes.
- Default value: false

### `openbao_start_pause_seconds`

- Some installations may need some time between the first OpenBao start
  and the first restart. Setting this to a value `>0` will add a pause
  time after the first OpenBao start.
- Default value: 0

## TCP Listener Variables

### `vault_tcp_listeners`

- A list of tcp listeners. Each listener can define any of the listener specific variables described in further detail below.
- Default value:
```yaml
vault_tcp_listeners:
  - vault_address: '{{ vault_address }}'
    vault_port: '{{ vault_port }}'
    vault_cluster_address: '{{ vault_cluster_address }}'
    # vault_proxy_protocol_behavior: '{{ vault_proxy_protocol_behavior }}'
    # vault_proxy_protocol_authorized_addrs: '{{ vault_proxy_protocol_authorized_addrs }}'
    vault_tls_disable: '{{ vault_tls_disable }}'
    vault_tls_certs_path: '{{ vault_tls_certs_path }}'
    vault_tls_private_path: '{{ vault_tls_private_path }}'
    vault_tls_cert_file: '{{ vault_tls_cert_file }}'
    vault_tls_key_file: '{{ vault_tls_key_file }}'
    vault_tls_ca_file: '{{ vault_tls_ca_file }}'
    vault_tls_min_version: '{{ vault_tls_min_version }}'
    vault_tls_cipher_suites: '{{ vault_tls_cipher_suites }}'
    vault_tls_require_and_verify_client_cert: '{{ vault_tls_require_and_verify_client_cert }}'
    vault_tls_disable_client_certs: '{{ vault_tls_disable_client_certs }}'
    # vault_x_forwarded_for_authorized_addrs: '{{ vault_x_forwarded_for_authorized_addrs }}'
    # vault_x_forwarded_for_hop_skips: '{{ vault_x_forwarded_for_hop_skips }}'
    # vault_x_forwarded_for_reject_not_authorized: '{{ vault_x_forwarded_for_reject_not_authorized }}'
    # vault_x_forwarded_for_reject_not_present: '{{ vault_x_forwarded_for_reject_not_present }}'
```

## Storage Backend Variables

### `vault_backend`

- Which storage backend should be selected, choices are: raft and file.
- Default value: raft

### `vault_backend_tls_src_files`

- User-specified source directory for TLS files for storage communication
- {{ vault_tls_src_files }}

### `vault_backend_tls_certs_path`

- Path to directory containing backend tls certificate files
- {{ vault_tls_certs_path }}

### `vault_backend_tls_private_path`

- Path to directory containing backend tls key files
- {{ vault_tls_private_path }}

### `vault_backend_tls_cert_file`

- Specifies the path to the certificate for backend communication (if supported).
- {{ vault_tls_cert_file }}

### `vault_backend_tls_key_file`

- Specifies the path to the private key for backend communication (if supported).
- {{ vault_tls_key_file }}

### `vault_backend_tls_ca_file`

- CA certificate used for backend communication (if supported). This defaults to system bundle if not specified.
- {{ vault_tls_ca_file }}

### Raft Storage Backend
#### `vault_raft_leader_tls_servername`

- TLS servername to use when connecting with HTTPS
- Default value: none

#### `vault_raft_group_name`

- Inventory group name of servers hosting the raft backend
- Default value: vault_raft_servers

### `vault_raft_cluster_members`

- Members of the raft cluster
- Default value: hosts in `vault_raft_group_name` group
- Can be used to override the behaviour of dynamically selecting all hosts in `vault_raft_group_name`
- Example:
  ```
  vault_raft_cluster_members:
    - peer: vault-host-1
      api_addr: https://vault-host-1:8200
    - peer: vault-host-2
      api_addr: https://vault-host-2:8200
    - peer: vault-host-3
      api_addr: https://vault-host-2:8200
  ```
- Setting the `vault_raft_cluster_members` statically enables you to run the role against a single host (instead of the entire host group)

#### `vault_raft_data_path`

- Data path for Raft
- Default value: openbao_data_path

#### `vault_raft_node_id`

- Node_id for Raft
- Default value: inventory_hostname_short

#### `vault_raft_performance_multiplier`

- Performance multiplier for Raft
- Default value: none

#### `vault_raft_trailing_logs`

- Logs entries count left on log store after snapshot
- Default value: none

#### `vault_raft_snapshot_threshold`

- Minimum Raft commit entries between snapshots
- Default value: none

#### `vault_raft_max_entry_size`

- Maximum number of bytes for a Raft entry
- Default value: none

#### `vault_raft_autopilot_reconcile_interval`

- Interval after which autopilot will pick up any state changes
- Default value: none

#### `vault_raft_cloud_auto_join`

- Defines any cloud auto-join metadata. If supplied, Vault will
  attempt to automatically discover peers in addition to what can
  be provided via `leader_api_addr`
- Default value: none

#### `vault_raft_cloud_auto_join_exclusive`

- If set to `true`, any `leader_api_addr` occurences will be removed
  from the configuration.
  Keeping this to `false` will allow `auto_join` and `leader_api_addr`
  to coexist
- Default value: false

#### `vault_raft_cloud_auto_join_scheme`

- URI scheme to be used for `auto_join`
- Default value: none (`https` is the default value set by
  Vault if not specified)

#### `vault_raft_cloud_auto_join_port`

- Port to be used for `auto_join`
- Default value: none (`8200` is the default value set by
  Vault if not specified)

### File Storage Backend

#### `vault_backend_file`

- Backend file template filename
- Default value: `backend_file.j2`

### Raft Integrated Storage Backend

#### `vault_backend_raft`

- Backend raft integrated storage template filename
- Default value: `vault_backend_raft.j2`

#### `vault_raft_node_id`

- Identifier for the node in the integrated storage Raft cluster
- Default value: "raft_node_1"

#### `vault_raft_retry_join`

- Details of all the nodes are known beforehand
- Default value: "[]"

##### `leader_api_addr`

- Address of a possible leader node.
- Default value: ""

##### `leader_ca_cert_file`

- File path to the CA cert of the possible leader node.
- Default value: ""

##### `leader_client_cert_file`

- File path to the client certificate for the follower node to establish client authentication with the possible leader node.
- Default value: ""

##### `leader_client_key_file`

- File path to the client key for the follower node to establish client authentication with the possible leader node.
- Default value: ""

##### `leader_ca_cert`

- CA cert of the possible leader node.
- Default value: ""

##### `leader_client_cert`

- Client certificate for the follower node to establish client authentication with the possible leader node.
- Default value: ""

##### `leader_client_key`

- Client key for the follower node to establish client authentication with the possible leader node.
- Default value: ""

### `vault_log_level`

- [Log level](https://www.consul.io/docs/agent/options.html#_log_level)
  - Supported values: trace, debug, info, warn, err
- Default value: info
- Requires Vault version 0.11.1 or higher

### `vault_iface`

- Network interface
  - Can be overridden with `VAULT_IFACE` environment variable
- Default value: eth1

### `vault_address`

- Primary network interface address to use
- Default value: `"{{ hostvars[inventory_hostname]['ansible_'+vault_iface]['ipv4']['address'] }}"`

### `vault_port`

- TCP port number to on which to listen
- Default value: 8200

### `vault_max_lease_ttl`

- Configures the [maximum possible lease duration](https://www.vaultproject.io/docs/config/#max_lease_ttl) for tokens and secrets.
- Default value: 768h (32 days)

### `vault_default_lease_ttl`

- Configures the [default lease duration](https://www.vaultproject.io/docs/config/#default_lease_ttl) for tokens and secrets.
- Default value: 768h (32 days)

### `vault_main_config`
- Main configuration file name (full path)
- Default value: `"{{ openbao_config_path }}/vault_main.hcl"`

### `vault_main_configuration_template`

- Vault main configuration template file
- Default value: *vault_main_configuration.hcl.j2*

### `vault_custom_configuration`

- Vault custom configuration
- Default value: none

### `vault_http_proxy`

- Address to be used as the proxy for HTTP and HTTPS requests unless overridden by `vault_https_proxy` or `vault_no_proxy`
- Default value: `""`

### `vault_https_proxy`

- Address to be used as the proxy for HTTPS requests unless overridden by `vault_no_proxy`
- Default value: `""`

### `vault_no_proxy`

- Comma separated values which specify hosts that should be exluded from proxying.  Follows [golang conventions](https://godoc.org/golang.org/x/net/http/httpproxy)
- Default value: `""`

### `vault_cluster_address`

- Address to bind to for cluster server-to-server requests
- Default value: `"{{ hostvars[inventory_hostname]['ansible_'+vault_iface]['ipv4']['address'] }}:{{ (vault_port | int) + 1}}"`

### `vault_cluster_addr`

- Address to advertise to other Vault servers in the cluster for request forwarding
- Default value: `"{{ vault_protocol }}://{{ vault_cluster_address }}"`

### `vault_api_addr`

- [HA Client Redirect address](https://www.vaultproject.io/docs/concepts/ha.html#client-redirection)
- Default value: `"{{ vault_protocol }}://{{ vault_redirect_address or hostvars[inventory_hostname]['ansible_'+vault_iface]['ipv4']['address'] }}:{{ vault_port }}"`
  - vault_redirect_address is kept for backward compatibility but is deprecated.

### `vault_disable_api_health_check`

- flag for disabling the health check on vaults api address
- Default value: `false`

### `vault_cluster_disable`

- Disable HA clustering
- Default value: false

### `validate_certs_during_api_reachable_check`

- Disable Certificate Validation for API reachability check
- Default value: true

### `vault_proxy_protocol_behavior`

- May be one of `use_always`, `allow_authorized`, or `deny_unauthorized`
- Enables [PROXY protocol](https://www.vaultproject.io/docs/configuration/listener/tcp#proxy_protocol_behavior) for listener.
- If enabled and set to something other than `use_always`, you must also set
  - [*vault_proxy_protocol_authorized_addrs*](https://www.vaultproject.io/docs/configuration/listener/tcp#proxy_protocol_authorized_addrs)
  - Comma-separated list of source IPs for which PROXY protocol information will be used.
- Default value: ""

### `vault_tls_certs_path`

- Path to TLS certificates
- Default value `/etc/vault/tls`

### `vault_tls_private_path`

- Path to TLS keys
- Default value `/etc/vault/tls`

### `vault_tls_disable`

- [Disable TLS](https://www.vaultproject.io/docs/configuration/listener/tcp.html#tls_disable)
  - Can be overridden with `VAULT_TLS_DISABLE` environment variable
- Default value: 1

### `vault_tls_gossip`

- Enable TLS Gossip to storage (if supported)
- Default value: 0

### `vault_tls_src_files`

- User-specified source directory for TLS files
  - Override with `VAULT_TLS_SRC_FILES` environment variable
- Default value: `{{ role_path }}/files`

### `vault_tls_ca_file`

- CA certificate filename
  - Override with `VAULT_TLS_CA_CRT` environment variable
- Default value: `ca.crt`

### `vault_tls_client_ca_file`

- Client CA certificate filename
- Default value: ``

### `vault_tls_cert_file`

- Server certificate
  - Override with `VAULT_TLS_CERT_FILE` environment variable
- Default value: `server.crt`

### `vault_tls_key_file`

- Server key
  - Override with `VAULT_TLS_KEY_FILE` environment variable
- Default value: `server.key`

### `vault_tls_min_version`

- [Minimum acceptable TLS version](https://www.vaultproject.io/docs/configuration/listener/tcp.html#tls_min_version)
  - Can be overridden with `VAULT_TLS_MIN_VERSION` environment variable
- Default value: tls12

### `vault_tls_cipher_suites`

- [Comma-separated list of supported ciphersuites](https://www.vaultproject.io/docs/configuration/listener/tcp.html#tls_cipher_suites)
- Default value: ""

### `vault_tls_require_and_verify_client_cert`

- [Require clients to present a valid client certificate](https://www.vaultproject.io/docs/configuration/listener/tcp.html#tls_require_and_verify_client_cert)
- Default value: false

### `vault_tls_disable_client_certs`

- [Disable requesting for client certificates](https://www.vaultproject.io/docs/configuration/listener/tcp.html#tls_disable_client_certs)
- Default value: false

### `vault_tls_copy_keys`

- Copy TLS files from src to dest
- Default value: true

### `vault_tls_files_remote_src`

- Copy from remote source if TLS files are already on host
- Default value: false

### `vault_x_forwarded_for_authorized_addrs`

- Comma-separated list of source IP CIDRs for which an X-Forwarded-For header will be trusted.
- Enables [X-Forwarded-For support.](https://www.vaultproject.io/docs/configuration/listener/tcp#x_forwarded_for_authorized_addrs)
- If enabled, you may also set any of the following parameters:
  - *vault_x_forwarded_for_hop_skips* with a format of "N" for the number of hops to skip
  - *vault_x_forwarded_for_reject_not_authorized* with true/false
  - *vault_x_forwarded_for_reject_not_present* with true/false
- Default value: ""

### `vault_systemd_template`
- Systemd service template file
- Default value: `vault_service_systemd.j2`

### `vault_systemd_service_name`
- Systemd service unit name
- Default value: "vault"

### `vault_telemetry_enabled`
- Enable [Vault telemetry](https://www.vaultproject.io/docs/configuration/telemetry.html)
- If enabled, you must set at least one of the following parameters according to your telemetry provider:
  - *vault_statsite_address* with a format of "FQDN:PORT"
  - *vault_statsd_address* with a format of "FQDN:PORT"
  - *vault_prometheus_retention_time* e.g: "30s" or "24h"
- If enabled, optionally set *vault_telemetry_disable_hostname* to strip the hostname prefix from telemetry data
- Default value: *false*

### `vault_unauthenticated_metrics_access`

- Configure [unauthenticated metrics access](https://www.vaultproject.io/docs/configuration/listener/tcp#configuring-unauthenticated-metrics-access)
- Default value: false

### `vault_telemetry_usage_gauge_period`

- Specifies the interval at which high-cardinality usage data is collected,
such as token counts, entity counts, and secret counts.
- Default value: *undefined*

## Dependencies

> **NOTE**: Read these before executing the role to avoid certain frequently
encountered issues which are resolved by installing the correct dependencies.

### `gtar`

Ansible requires GNU tar and this role performs some local use of the
unarchive module, so ensure that your system has `gtar` installed.

### Python netaddr

The role depends on `python-netaddr` so:

```
pip install netaddr
```

on the Ansible control host prior to executing the role.


## Original Author Information

[Brian Shumate](http://brianshumate.com)

## Contributors To Original Project

Special thanks to the folks listed in [CONTRIBUTORS.md](https://github.com/ansible-community/ansible-vault/blob/6e61e78c062e82681cb6f7ff9c0e62f6d7a0102b/CONTRIBUTORS.md) for their
contributions to this project.
