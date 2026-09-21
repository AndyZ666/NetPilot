from ncclient import manager
from getpass import getpass

HOST = "172.20.20.4"
USERNAME = "admin"
PASSWORD = getpass("Password: ")

config = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <interfaces xmlns="http://openconfig.net/yang/interfaces">
    <interface>
      <name>Ethernet2</name>
      <config>
        <name>Ethernet2</name>
        <description>to-S4-Eth2</description>
      </config>
    </interface>
  </interfaces>
</config>
"""

with manager.connect(
    host=HOST,
    port=830,
    username=USERNAME,
    password=PASSWORD,
    hostkey_verify=False,
    allow_agent=False,
    look_for_keys=False,
    timeout=30,
) as m:

    print("\nNETCONF CONNECTION SUCCESSFUL")
    print("Session ID:", m.session_id)

    reply = m.edit_config(
        target="running",
        config=config,
        default_operation="merge"
    )

    print("\nEDIT-CONFIG RESULT:")
    print(reply)