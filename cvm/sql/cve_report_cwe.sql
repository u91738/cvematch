SELECT cwe.cwe_id,
       cwe.cwe_name,
       cwe.description
FROM cve
LEFT JOIN cwe_classification ON cve.cve_id = cwe_classification.cve_id
LEFT JOIN cwe ON cwe.cwe_id = cwe_classification.cwe_id
WHERE cve.cve_id = ?
