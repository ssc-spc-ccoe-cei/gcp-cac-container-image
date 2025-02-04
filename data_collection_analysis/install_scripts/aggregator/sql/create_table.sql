CREATE TABLE
    `$PROJECT_ID.$DATA_SET.$TABLE_NAME` (
        organization STRING NOT NULL OPTIONS 
        (description = "Organization Display Name"
        ),
        status:STRING NOT NULL OPTIONS (
            description = "Compliance Status"
            ),
        profile_level INT64 NOT NULL OPTIONS (
            description = "GC Cloud Profile Level"
            ),
        description STRING NOT NULL OPTIONS (
            description = "GR Description"
            ),
        asset_name STRING OPTIONS (
            description = "Cloud Resource"
            ),
        msg:STRING NOT NULL OPTIONS (
            description = "Compliance output"
            ),
        organization_id INT64 NOT NULL OPTIONS (
            description = "Numeric Identifier for Organization"
        ),
        guardrail INT64 NOT NULL OPTIONS (
            description = "Guardrail Number"
            ),
        check_type STRING NOT NULL OPTIONS (
            description = "Type of Check in RECOMMENDED or MANDATORY"
        ), 
        timestamp DATE NOT NULL OPTIONS(
            description = "Date of last check"
        )
    ) CLUSTER BY organization,
    guardrail;




