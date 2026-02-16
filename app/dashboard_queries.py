import duckdb
import pandas as pd

GOLD = "data/gold/incident_intelligence_gold_v4.csv"

con = duckdb.connect()

df = con.execute(f"SELECT * FROM read_csv_auto('{GOLD}', ignore_errors=true)").df()

# Top recurring FAILURE packages
top_fail = (
    df[df["incident_type"].str.upper() == "FAILURE"]
    .groupby(["package_name_inferred","error_family_v3"])
    .size()
    .reset_index(name="cnt")
    .sort_values("cnt", ascending=False)
    .head(25)
)

# Daily trend (FAILURE count per day)
df["run_start_time"] = pd.to_datetime(df["run_start_time"], errors="coerce")
trend = (
    df[df["incident_type"].str.upper() == "FAILURE"]
    .assign(day=lambda x: x["run_start_time"].dt.date)
    .groupby("day").size().reset_index(name="failures")
    .sort_values("day")
)

top_fail.to_csv("state/dashboard_top_failures.csv", index=False)
trend.to_csv("state/dashboard_failure_trend.csv", index=False)

print("Wrote:")
print(" - state/dashboard_top_failures.csv")
print(" - state/dashboard_failure_trend.csv")

