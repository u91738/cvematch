-- get CVEFixes 1.0.7 from 20 Gb to 2.3, add indices
DROP TABLE commits;
DROP TABLE method_change;
DROP TABLE repository;

ALTER TABLE file_change DROP COLUMN change_type;
ALTER TABLE file_change DROP COLUMN diff_parsed;
ALTER TABLE file_change DROP COLUMN num_lines_added;
ALTER TABLE file_change DROP COLUMN num_lines_deleted;
ALTER TABLE file_change DROP COLUMN nloc;
ALTER TABLE file_change DROP COLUMN complexity;
ALTER TABLE file_change DROP COLUMN token_count;

ALTER TABLE cve DROP COLUMN published_date;
ALTER TABLE cve DROP COLUMN last_modified_date;
ALTER TABLE cve DROP COLUMN nodes;
ALTER TABLE cve DROP COLUMN cvss2_vector_string;
ALTER TABLE cve DROP COLUMN cvss2_access_vector;
ALTER TABLE cve DROP COLUMN cvss2_access_complexity;
ALTER TABLE cve DROP COLUMN cvss2_authentication;
ALTER TABLE cve DROP COLUMN cvss2_confidentiality_impact;
ALTER TABLE cve DROP COLUMN cvss2_integrity_impact;
ALTER TABLE cve DROP COLUMN cvss2_availability_impact;
ALTER TABLE cve DROP COLUMN cvss2_base_score;
ALTER TABLE cve DROP COLUMN cvss3_vector_string;
ALTER TABLE cve DROP COLUMN cvss3_attack_vector;
ALTER TABLE cve DROP COLUMN cvss3_attack_complexity;
ALTER TABLE cve DROP COLUMN cvss3_privileges_required;
ALTER TABLE cve DROP COLUMN cvss3_user_interaction;
ALTER TABLE cve DROP COLUMN cvss3_scope;
ALTER TABLE cve DROP COLUMN cvss3_confidentiality_impact;
ALTER TABLE cve DROP COLUMN cvss3_integrity_impact;
ALTER TABLE cve DROP COLUMN cvss3_availability_impact;
ALTER TABLE cve DROP COLUMN cvss3_base_score;
ALTER TABLE cve DROP COLUMN cvss3_base_severity;
ALTER TABLE cve DROP COLUMN exploitability_score;
ALTER TABLE cve DROP COLUMN impact_score;
ALTER TABLE cve DROP COLUMN ac_insuf_info;
ALTER TABLE cve DROP COLUMN reference_json;
ALTER TABLE cve DROP COLUMN problemtype_json;

VACUUM;

CREATE INDEX IF NOT EXISTS fixes_cve_id ON fixes (cve_id);
CREATE INDEX IF NOT EXISTS file_change_programming_language ON file_change (programming_language);

-- C and C++ data has plenty of CSS and other off-topic stuff
CREATE VIEW IF NOT EXISTS file_change_cpp(file_change_id, hash, diff, code_after, code_before)
AS
SELECT file_change_id, hash, diff, code_after, code_before
FROM file_change
WHERE (programming_language = 'C' OR programming_language = 'C++')
AND (
    filename LIKE '%.c'
    OR filename LIKE '%.cpp'
    OR filename LIKE '%.h'
    OR filename LIKE '%.cc'
    OR filename LIKE '%.inc'
    OR filename LIKE '%.hpp'
    OR filename LIKE '%.cxx'
    OR filename LIKE '%.in'
    OR filename LIKE '%.xs'
    OR filename LIKE '%.hh'
    OR filename LIKE '%.ci'
    OR filename LIKE '%.l'
    OR filename LIKE '%.c++'
    OR filename LIKE '%.pro'
    OR filename LIKE '%.def'
    OR filename LIKE '%.xst'
    OR filename LIKE '%.edl'
    OR filename LIKE '%.re'
    OR filename LIKE '%.y'
);
