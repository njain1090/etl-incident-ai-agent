# Missing Object or Permission (SQL Server / SSIS)

## Symptom
- Cannot find the object "<X>" because it does not exist or you do not have permissions
- Could not find stored procedure "<X>"
- Invalid object name "<X>"

## Meaning
1) Object missing in target DB/schema (deployment drift / wrong DB), OR
2) Execution identity lacks permission, OR
3) SSIS connection manager points to wrong environment.

## Restart policy
Do NOT rerun blindly. Rerun will fail until object/permission is fixed.

## Checklist
1) Confirm SSIS Connection Manager target DB/server for the failing task.
2) Verify object existence (table/view/proc) in that DB + schema.
3) Verify schema: reportteam.<X> vs dbo.<X>.
4) Verify permissions for SSIS run account / SQL Agent proxy.
5) If object missing, check deployment history and request DDL/proc deployment.

## Escalation
MED → Data Engineering (package owner); MED → DBA if grants/deployment needed.

