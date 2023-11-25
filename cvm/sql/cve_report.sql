SELECT cve.cve_id,
       cve.description -> '[0].value' as cve_desc,
       file_change_cpp.diff
FROM file_change_cpp
LEFT JOIN fixes  ON fixes.hash = file_change_cpp.hash
LEFT JOIN cve ON fixes.cve_id = cve.cve_id
WHERE file_change_id = ?
