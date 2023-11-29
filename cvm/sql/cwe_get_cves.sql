SELECT cve.cve_id
FROM cve
LEFT JOIN cwe_classification ON cwe_classification.cve_id = cve.cve_id
WHERE cwe_classification.cwe_id = ?
