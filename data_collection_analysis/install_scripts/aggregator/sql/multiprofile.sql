CREATE OR REPLACE TABLE
  `<project_id>.<data_set>.multiprofile_output` AS (
  SELECT
    timestamp,
    organization_id,
    organization,
    tenant_domain,
    profile_level AS organization_profile,
    CASE
      WHEN proj_profile IS NOT NULL THEN proj_profile
      ELSE profile_level
    END
    AS profile_level,
    proj_parent AS project_name,
    guardrail,
    validation,
    description,
    msg,
    status,
    asset_name,
    app_version,
    policy_version,
  FROM
    `<project_id>.<data_set>.raw_results`
  ORDER BY
    organization_id,
    guardrail,
    validation 
    );
UPDATE
  `<project_id>.<data_set>.multiprofile_output`
SET
  status = "N/A"
WHERE
  ( 
    (profile_level = 1
      AND guardrail IN (
        3,
        5,
        6,
        7,
        9,
        10,
        11,
        13))
    OR 
    (profile_level = 2
      AND guardrail IN (
        5,
        6)) 
  )