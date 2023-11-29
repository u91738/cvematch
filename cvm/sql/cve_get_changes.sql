SELECT file_change_id, fixes.cve_id, cwe_classification.cwe_id, diff
FROM file_change_cpp
LEFT JOIN fixes  ON fixes.hash = file_change_cpp.hash
LEFT JOIN cve ON fixes.cve_id = cve.cve_id
LEFT JOIN cwe_classification ON cwe_classification.cve_id = cve.cve_id
WHERE fixes.cve_id = ?
