#!/usr/bin/env python3
"""Run the existing S3 NETCONF example using the shared credential provider."""

from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security.credential_provider import get_credentials

HOST = "172.20.20.4"

INTERFACE_FILTER = """
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
            type="subtree">
    <interfaces xmlns="http://openconfig.net/yang/interfaces"/>
    </filter>
    """


def main():
    try:
        from ncclient import manager
    except ImportError:
        print("Install the dependency: python3 -m pip install ncclient")
        return 1
    try:
        username, password = get_credentials()
        if not username or not password:
            raise ValueError
    except Exception:
        print("Device credentials are not available from the credential provider.")
        return 1
    try:
        with manager.connect(
            host=HOST, port=830, username=username, password=password,
            hostkey_verify=False, allow_agent=False, look_for_keys=False,
            timeout=30,
        ) as session:
            print("\nNETCONF CONNECTION SUCCESSFUL")
            print("Session ID:", session.session_id)
            print("\nRetrieving running configuration...\n")
            reply = session.get_config(source="running", filter=INTERFACE_FILTER)
            if reply.errors:
                raise RuntimeError("NETCONF retrieval was rejected.")
            print(reply.data_xml)
    except Exception:
        print("NETCONF operation failed; check device reachability and authorization.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
