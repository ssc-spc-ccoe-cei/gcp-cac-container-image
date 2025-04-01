SELECT DISTINCT
    ORGANIZATION,
    profile_level,
    CASE
        WHEN profile_level = 1 THEN CASE
            WHEN (
                SELECT
                    COUNT(*)
                FROM
                    `<project_id>.<data_set>.multiprofile_output`
                WHERE
                    profile_level = 1
                    AND status = 'NON-COMPLIANT'
                    AND guardrail IN (1, 2, 4, 8, 12)
            ) > 0 THEN 'NON-COMPLIANT'
            ELSE 'COMPLIANT'
        END
        WHEN profile_level = 2 THEN CASE
            WHEN (
                SELECT
                    COUNT(*)
                FROM
                    `<project_id>.<data_set>.multiprofile_output`
                WHERE
                    profile_level = 2
                    AND status = 'NON-COMPLIANT'
                    AND guardrail IN (1, 2, 3, 4, 7, 8, 9, 10, 11, 12,13)
            ) > 0 THEN 'NON-COMPLIANT'
            ELSE 'COMPLIANT'
        END
        WHEN profile_level >= 3 THEN CASE
            WHEN (
                SELECT
                    COUNT(*)
                FROM
                    `<project_id>.<data_set>.multiprofile_output`
                WHERE
                    profile_level >= 3
                    AND status = 'NON-COMPLIANT'
            ) > 0 THEN 'NON-COMPLIANT'
            ELSE 'COMPLIANT'
        END
    END
FROM
    `<project_name>.<data_set>.multiprofile_output`




