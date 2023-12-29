-- get CVEFixes 1.0.7 from 20 Gb to 2.1, add indices
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

-- Dataset is quite dirty
DELETE
FROM file_change
WHERE programming_language IN ('unknown', 'TeX', 'Markdown', 'None', 'Jupyter Notebook', 'CSS');

-- C and C++ data has plenty of CSS and other off-topic stuff
DELETE
FROM file_change
WHERE (programming_language = 'C' OR programming_language = 'C++')
       AND (
            filename NOT LIKE '%.c'
            AND filename NOT LIKE '%.cpp'
            AND filename NOT LIKE '%.h'
            AND filename NOT LIKE '%.cc'
            AND filename NOT LIKE '%.inc'
            AND filename NOT LIKE '%.hpp'
            AND filename NOT LIKE '%.cxx'
            AND filename NOT LIKE '%.in'
            AND filename NOT LIKE '%.xs'
            AND filename NOT LIKE '%.hh'
            AND filename NOT LIKE '%.ci'
            AND filename NOT LIKE '%.l'
            AND filename NOT LIKE '%.c++'
            AND filename NOT LIKE '%.pro'
            AND filename NOT LIKE '%.def'
            AND filename NOT LIKE '%.xst'
            AND filename NOT LIKE '%.edl'
            AND filename NOT LIKE '%.re'
            AND filename NOT LIKE '%.y'
        );

DELETE
FROM file_change
WHERE (programming_language = 'Java'
       AND (filename NOT LIKE '%.java' AND filename NOT LIKE '%.jsp'));

DELETE
FROM file_change
WHERE (programming_language = 'C#' AND filename NOT LIKE '%.cs');

DELETE
FROM file_change
WHERE (programming_language = 'Go' AND filename NOT LIKE '%.go');

DELETE
FROM file_change
WHERE (programming_language = 'Python' AND filename NOT LIKE '%.py');

DELETE
FROM file_change
WHERE code_before = 'None';

VACUUM;

CREATE INDEX IF NOT EXISTS fixes_cve_id ON fixes (cve_id);
CREATE INDEX IF NOT EXISTS file_change_programming_language ON file_change (programming_language);
