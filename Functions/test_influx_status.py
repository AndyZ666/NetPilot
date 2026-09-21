import os
from influxdb_client import InfluxDBClient

URL = "http://127.0.0.1:8086"
ORG = "NetPilot"
BUCKET = "telemetry"
TOKEN = os.getenv("INFLUX_TOKEN")

if not TOKEN:
    raise RuntimeError("INFLUX_TOKEN is not set")

client = InfluxDBClient(
    url=URL,
    token=TOKEN,
    org=ORG
)

query = f'''
from(bucket: "{BUCKET}")
  |> range(start: -30d)
  |> filter(fn: (r) =>
      r["_measurement"] == "interface_oper_status" and
      r["_field"] == "oper_status"
  )
  |> group(columns: ["source", "name"])
  |> last()
  |> keep(columns: ["_time", "source", "name", "_value"])
'''

tables = client.query_api().query(query=query, org=ORG)

results = []

for table in tables:
    for record in table.records:
        results.append({
            "source": record.values.get("source"),
            "interface": record.values.get("name"),
            "status": record.get_value(),
            "time": record.get_time(),
        })

results.sort(key=lambda x: (x["source"], x["interface"]))

print("\nLatest Interface Operational Status")
print("-" * 75)
print(f"{'SOURCE':<16} {'INTERFACE':<18} {'STATUS':<8} LAST UPDATE")
print("-" * 75)

for item in results:
    print(
        f"{item['source']:<16} "
        f"{item['interface']:<18} "
        f"{item['status']:<8} "
        f"{item['time']}"
    )

print("-" * 75)

sources = sorted(set(x["source"] for x in results))

print(f"\nInterfaces found: {len(results)}")
print(f"Devices found:    {len(sources)}")
print("Sources:")

for source in sources:
    print(f"  {source}")

client.close()
