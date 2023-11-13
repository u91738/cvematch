SELECT cve.cve_id as cve_id, cwe_classification.cwe_id as cwe_id, description -> '[0].value' as desc
FROM cve
LEFT JOIN cwe_classification  ON cwe_classification.cve_id = cve.cve_id
ORDER BY cwe_classification.cwe_id, cve.cve_id
