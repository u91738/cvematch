SELECT cve.cve_id,
       cve.description -> '[0].value' as cve_desc,
       cwe.cwe_id,
       cwe.cwe_name,
       cwe.description as cwe_desc,
       file_change_cpp.diff
FROM file_change_cpp
LEFT JOIN fixes  ON fixes.hash = file_change_cpp.hash
LEFT JOIN cve ON fixes.cve_id = cve.cve_id
LEFT JOIN cwe_classification ON cve.cve_id = cwe_classification.cve_id
LEFT JOIN cwe ON cwe.cwe_id = cwe_classification.cwe_id
WHERE file_change_id = ?
