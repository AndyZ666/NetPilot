from ncclient import manager
from getpass import getpass

HOST = "172.20.20.4"
USERNAME = "admin"
PASSWORD = getpass("Password: ")

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

    print("\nRetrieving running configuration...\n")

    interface_filter = """
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
            type="subtree">
    <interfaces xmlns="http://openconfig.net/yang/interfaces"/>
    </filter>
    """

    reply = m.get_config(
        source="running",
        filter=interface_filter
    )

    print(reply.data_xml)