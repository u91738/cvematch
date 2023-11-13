SELECT cwe.cwe_id as cwe_id, cwe_name, count(*) as cve_count, cwe.description as desc
FROM cwe
LEFT JOIN cwe_classification  ON cwe.cwe_id = cwe_classification.cwe_id
LEFT JOIN cve  ON cwe_classification.cve_id = cve.cve_id
GROUP BY cwe.cwe_id
