SELECT
    msg,
    `organization`,
    status,
    guardrail,
    check_type,
    timestamp
FROM
    ``
WHERE
    status != 'COMPLIANT'
    AND check_type = "MANDATORY"
ORDER BY
    ORGANIZATION,
    guardrail