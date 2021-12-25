# Ansible TP-Link business line switches module

Ansible Galaxy module for TP-Link business line switches - T1500, T1600, TL-SG3452P, TL-SG3428X

## Install

```
ansible-galaxy collection install community.tplink
```

## Use
Tested on devices:
* T1500-10PS
* T1600-28PS
* TL-SG3452P
* TL-SG3428X

The TP-Link T1700G-28TQ switches unfortunately do not work due to a firmware bug. The 'NO CLIPAGING'
command is advertised as supported in the manuals, however it's not implemented in the firmware.
We have requested TP-Link to bring out a new firmware version that does implement this required command.

Tested on Python versions:
* 3.6
* 3.7
* 3.8
* 3.9

file `tplink_inv.yml`
```yaml
all:
  vars:
    # no automatic facts
    gather_facts: no  
    
    ansible_connection: network_cli
    ### change what you need
    # ansible_ssh_private_key_file: /dir/private.key
    # ansible_ssh_user: user
    # ansible_ssh_pass: password

  hosts:
    switch1:
      ansible_host: AAA.BBB.CCC.DDD
      ansible_network_os: community.tplink.tplink
    switch2:
      ansible_host: WWW.XXX.YYY.ZZZ
      ansible_network_os: community.tplink.tplink

```

playbook `tplink_facts.yml`
```yaml
- name: Gather Facts
  gather_facts: no
  hosts: all
  vars:
    - configs_dir: configs

  tasks:
    ###
    # Collect data
    #
    - name: TP-Link - Gather Facts - subset default
      communtity.tplink.facts:
        gather_subset:
          - default

    - name: TP-Link - Gather Facts - subset config
      community.tplink.facts:
        gather_subset:
          - config

    - name: Create configuration directory
      local_action: file path={{ configs_dir }} state=directory
      run_once: true
      check_mode: no
      changed_when: no

    - name: Save running config
      local_action: copy content={{ ansible_net_config }} dest={{ configs_dir }}/{{ inventory_hostname }}_net_config
```

Run
```
ansible-playbook -i tplink_inv.yml tplink_facts.yml
```

## Developement

### Setup environment

### Develop 

### Testing


### Release 

## Releasing, Versioning and Deprecation

See [RELEASE_POLICY.md](./RELEASE_POLICY.md)

## Code of Conduct

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)
