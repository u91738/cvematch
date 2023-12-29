SELECT cve.cve_id,
       cve.description -> '[0].value' as cve_desc,
       file_change.diff
FROM file_change
LEFT JOIN fixes  ON fixes.hash = file_change.hash
LEFT JOIN cve ON fixes.cve_id = cve.cve_id
WHERE file_change_id = ?
