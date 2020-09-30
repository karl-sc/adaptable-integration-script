import sys
#Log level 0 = Debug, 1 = Info, 2= Warn, 3 = Error
def cgx_log(log_level=1, message = ""):
  if log_level == 1:
    print("INFO :",message)
  elif log_level == 2:
    print("WARN :",message)
    pass
  elif log_level == 3:
    print("ERROR:",message)
  elif log_level == 0:
    print("DEBUG:",message)
    pass
  else:
    print("UNK:",message)

### This function validates the input variables to the defined variables in the JINJA Template
def cgx_validate_vars(yml_file, input_dict, strict=False):
  #### Use Regex to get all defined YML JINJA Vars in the YML File
  import re
  jinja_vars = re.findall("{{.*}}",yml_file)
  lst_jinja_vars = []
  for found_var in jinja_vars:
    cleaned_var = found_var.replace("}}","").replace("{{","").strip()
    if cleaned_var not in lst_jinja_vars:
        lst_jinja_vars.append(cleaned_var)

  #### Check that all JINJA variables have a corresponding input
  strict_flag_error = False
  for input_var in lst_jinja_vars:
    if input_var in input_dict.keys():
      cgx_log(0,"JINJA input Variable and Input Variable matched '" + input_var + "'")
    else:
      cgx_log(2,"JINJA input Variable has no matching input:  '" + input_var + "'")
      strict_flag_error = True
  
  ### if we have strict checking, return whether or not we had some JINJA Vars with no input
  if strict:
    return strict_flag_error
  else:
    return True


def cgx_render_jinja(yml_file, input_dict):
    import jinja2
    template = jinja2.Environment(loader=jinja2.BaseLoader()).from_string(yml_file)
    try:
      out_template =  template.render(input_dict)
      return out_template
    except jinja2.exceptions.UndefinedError:
      err_exception = sys.exc_info()
      print(err_exception[1])
      cgx_log(2,"Failed to render")
      return False
    except:
      err_exception = sys.exc_info()
      cgx_log(2,"Failed to render")
      return False

def cgx_yml_to_dict(do_site_yml):
  try:
    import yaml
    python_dict = yaml.safe_load(do_site_yml)
    return python_dict
  except yaml.parser.ParserError:
    err_exception = sys.exc_info()
    print(sys.exc_info()[1])
    return False
  except:
    err_exception = sys.exc_info()
    print(sys.exc_info()[0])
    return False

def cgx_auth(auth_token):
    try:
        from cloudgenix import API
        sdk = API()
        if (sdk.interactive.use_token(auth_token)):
            return sdk
        else:
            return False
    except:
        return False

def cgx_create_site(sdk, do_site_dict):
    from cloudgenix_config import do
    result = do.do_site(do_site_dict, destroy=False, passed_sdk=sdk, )
    print(result)
    return True

#------------------------------#
def cgx_run(yml_file, auth_token, input_dict):
  
  ### Attempt to validate parameters
  if not (cgx_validate_vars(yml_file, input_dict)):
    cgx_log(3,"EXITING. Fatal error in parameter validation")
    return False
  
  ### Attempt to render the new JINJA Template File
  do_site_yml = cgx_render_jinja(yml_file, input_dict)
  if not (do_site_yml):
    cgx_log(3,"EXITING. Fatal error in rendering new Jinja YML SITE")
    return False
    
  ### Convert do_site_yml to a python dict
  do_site_dict = cgx_yml_to_dict(do_site_yml)
  if not (do_site_dict):
    cgx_log(3,"EXITING. Fatal error in converting new YML to python DICT")
    return False

  ### Attempt to validate SDK Authentication
  sdk = cgx_auth(auth_token)
  if not sdk:
    cgx_log(3,"EXITING. Fatal error in authentication")
    return False
  
  ### Attempt to do_site with rendered jinja
  if not cgx_create_site(sdk,do_site_dict):
    cgx_log(3,"EXITING. Fatal error in executing do_site")
    return False
  else:
    cgx_log(1,"Pushed Config Successfully")



















auth_token = "ASdasdasd"

yml_file = """
---
type: cloudgenix template
version: 1.0
sites v4.5:
  {{ site_name }}:
    address:
      city: {{ city }}
      country: {{ country }}
      post_code: {{ post_code }}
      state: {{ state }}
      street: {{ street1 }}
      street2: {{ street2 }}
    admin_state: active
    description: ''
    dhcpservers v2.1:
    - broadcast_address: {{ br1_prefix }}.255
      custom_options:
      default_lease_time: 43200
      description:
      disabled: false
      dns_servers:
      - 8.8.8.8
      domain_name:
      gateway: {{ br1_prefix }}.1
      ip_ranges:
      - end_ip: {{ br1_prefix }}.20
        start_ip: {{ br1_prefix }}.10
      max_lease_time: 86400
      network_context_id:
      static_mappings:
      subnet: {{ br1_prefix }}.0/24
      tags:
    element_cluster_role: SPOKE
    elements v2.3:
      {{ion_hostname}}:
        admin_action:
        allowed_roles:
        - HUB
        - SPOKE
        cluster_insertion_mode:
        cluster_member_id:
        connected: true
        deployment_op:
        description:
        element_security_zones v2.0: []
        interfaces v4.9:
          '1.{{ inet1_vlan }}':
            admin_up: true
            attached_lan_networks:
            bound_interfaces:
            bypass_pair:
            description:
            devicemgmt_policysetstack_id:
            dhcp_relay:
            directed_broadcast: false
            ethernet_port:
              full_duplex: false
              speed: 0
            ipv4_config:
              dhcp_config:
              dns_v4_config:
                name_servers:
                - 8.8.8.8
              routes:
              - destination: 0.0.0.0/0
                via: {{ inet1_gw }}
              static_config:
                address: {{ inet1_ip_cidr }}
              type: static
            mac_address:
            mtu: 0
            nat_address:
            nat_pools:
            nat_port: 0
            nat_zone_id: internet
            network_context_id:
            parent: '1'
            pppoe_config:
            scope: local
            service_link_config:
            site_wan_interface_ids:
            - BR1-Frontier2
            sub_interface:
              native_vlan: false
              vlan_id: {{ inet1_vlan }}
            tags:
            type: subinterface
            used_for: public
          '1.{{inet2_vlan}}':
            admin_up: true
            attached_lan_networks:
            bound_interfaces:
            bypass_pair:
            description:
            devicemgmt_policysetstack_id:
            dhcp_relay:
            directed_broadcast: false
            ethernet_port:
              full_duplex: false
              speed: 0
            ipv4_config:
              dhcp_config:
              dns_v4_config:
                name_servers:
                - 8.8.8.8
              routes:
              - destination: 0.0.0.0/0
                via: {{ inet2_gw }}
              static_config:
                address: {{ inet2_ip_cidr }}
              type: static
            mac_address:
            mtu: 0
            nat_address:
            nat_pools:
            nat_port: 0
            nat_zone_id: internet
            network_context_id:
            parent: '1'
            pppoe_config:
            scope: local
            service_link_config:
            site_wan_interface_ids:
            - BR1-Comcast1
            sub_interface:
              native_vlan: false
              vlan_id: {{inet2_vlan}}
            tags:
            type: subinterface
            used_for: public
          '2':
            admin_up: true
            attached_lan_networks:
            bound_interfaces:
            bypass_pair:
            description: ''
            devicemgmt_policysetstack_id:
            dhcp_relay:
            directed_broadcast: false
            ethernet_port:
              full_duplex: false
              speed: 0
            ipv4_config:
            mac_address:
            mtu: 1500
            nat_address:
            nat_pools:
            nat_port: 0
            nat_zone_id:
            network_context_id:
            parent:
            pppoe_config:
            scope: local
            service_link_config:
            site_wan_interface_ids:
            sub_interface:
            tags:
            type: port
            used_for: none
          '3':
            admin_up: true
            attached_lan_networks:
            bound_interfaces:
            bypass_pair:
            description: ''
            devicemgmt_policysetstack_id:
            dhcp_relay:
            directed_broadcast: false
            ethernet_port:
              full_duplex: false
              speed: 0
            ipv4_config:
              dhcp_config:
              dns_v4_config:
              routes:
              static_config:
                address: {{ br1_prefix }}.1/24
              type: static
            mac_address:
            mtu: 1500
            nat_address:
            nat_pools:
            nat_port: 0
            nat_zone_id:
            network_context_id:
            parent:
            pppoe_config:
            scope: global
            service_link_config:
            site_wan_interface_ids:
            sub_interface:
            tags:
            type: port
            used_for: lan
          '4':
            admin_up: false
            attached_lan_networks:
            bound_interfaces:
            bypass_pair:
            description: ''
            devicemgmt_policysetstack_id:
            dhcp_relay:
            directed_broadcast: false
            ethernet_port:
              full_duplex: false
              speed: 0
            ipv4_config:
            mac_address:
            mtu: 1500
            nat_address:
            nat_pools:
            nat_port: 0
            nat_zone_id:
            network_context_id:
            parent:
            pppoe_config:
            scope: local
            service_link_config:
            site_wan_interface_ids:
            sub_interface:
            tags:
            type: port
            used_for: none
          controller 1:
            admin_up: true
            attached_lan_networks:
            bound_interfaces:
            bypass_pair:
            description: ''
            devicemgmt_policysetstack_id:
            dhcp_relay:
            directed_broadcast: false
            ethernet_port:
              full_duplex: false
              speed: 0
            ipv4_config:
              dhcp_config:
              dns_v4_config:
              routes:
              static_config:
              type: dhcp
            mac_address:
            mtu: 1500
            nat_address:
            nat_pools:
            nat_port: 0
            nat_zone_id:
            network_context_id:
            parent:
            pppoe_config:
            scope: local
            service_link_config:
            site_wan_interface_ids:
            sub_interface:
            tags:
            type: port
            used_for: none
        l3_direct_private_wan_forwarding: true
        l3_lan_forwarding: true
        model_name: ion 3102v
        nat_policysetstack_id:
        network_policysetstack_id:
        ntp v2.0:
        - description: Default NTP template created by super user.
          name: default
          ntp_servers:
          - host: 0.cloudgenix.pool.ntp.org
            max_poll: 10
            min_poll: 9
            version: 4
          - host: 1.cloudgenix.pool.ntp.org
            max_poll: 10
            min_poll: 9
            version: 4
          - host: 2.cloudgenix.pool.ntp.org
            max_poll: 10
            min_poll: 9
            version: 4
          - host: 3.cloudgenix.pool.ntp.org
            max_poll: 10
            min_poll: 9
            version: 4
          - host: time.nist.gov
            max_poll: 15
            min_poll: 13
            version: 4
          source_interface_ids:
          tags:
        priority_policysetstack_id:
        role: SPOKE
        routing:
          bgp:
            global_config v2.2:
              admin_distance: 20
              adv_interval: 1
              graceful_restart: false
              hold_time: 90
              keepalive_time: 30
              local_as_num:
              maximum_paths: 1
              md5_secret:
              multi_hop_limit: 1
              peer_auth_type: none
              peer_retry_time: 120
              prefix_adv_type: aggregate-auto
              prefix_adv_type_to_lan: default
              prefixes_to_adv_to_wan:
              router_id:
              stalepath_time: 120
          static v2.0: []
        serial_number: {{ ion_serial }}
        software_version: 5.2.5-b4
        spoke_ha_config:
        state: bound
        tags:
        tenant_id: ''
        toolkit v2.2:
          account_disable_interval: 5
          inactive_interval: 15
          otpkey_version: 1
          retry_login_count: 5
          ssh_enabled: true
          ssh_outbound_enabled: false
        vpn_to_vpn_forwarding: false
    extended_tags:
    location:
      description:
      latitude: 0
      longitude: 0
    nat_policysetstack_id: Default-NATPolicySetStack
    network_policysetstack_id: Default-PathPolicySetStack
    policy_set_id:
    priority_policysetstack_id: Default-QOSPolicySetStack
    security_policyset_id:
    service_binding: Preset Domain
    tags:
    waninterfaces v2.5:
      BR1-Comcast1:
        bfd_mode: aggressive
        bw_config_mode: manual
        bwc_enabled: true
        cost: 128
        description:
        label_id: Primary ISP
        link_bw_down: 5.0
        link_bw_up: 5.0
        lqm_config:
        lqm_enabled: true
        network_id: Comcast-1
        network_type: publicwan
        tags:
        type: publicwan
        vpnlink_configuration:
      BR1-Frontier2:
        bfd_mode: aggressive
        bw_config_mode: manual
        bwc_enabled: true
        cost: 128
        description:
        label_id: Second ISP
        link_bw_down: 20.0
        link_bw_up: 20.0
        lqm_config:
        lqm_enabled: true
        network_id: Frontier-2
        network_type: publicwan
        tags:
        type: publicwan
        vpnlink_configuration:
"""

auth_token = '[insert auth here]]'
input_dict = {}
input_dict["site_name"] = "BranchThree"
input_dict["city"] = "boulder"
input_dict["country"] = "US"
input_dict["post_code"] = "93010"
input_dict["state"] = "CA"
input_dict["street1"] = "1234 Fake Street"
input_dict["street2"] = ""
input_dict["br1_prefix"] = "10.3.1"
input_dict["inet1_gw"] = "198.51.100.9"
input_dict["inet1_ip_cidr"] = "198.51.100.10/30"
input_dict["inet2_gw"] = "203.0.113.9"
input_dict["inet2_ip_cidr"] = "203.0.113.10/30"
input_dict["ion_serial"] = "ac4b4d56-ffff-aaaa-7796-999906a0ffff"
input_dict["ion_hostname"] = "br3-ion"
input_dict["inet1_vlan"] = "35"
input_dict["inet2_vlan"] = "36"


cgx_run(yml_file, auth_token, input_dict)
