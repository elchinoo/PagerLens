-- Row MACs (hardening): the rows that grant access or carry trust get a `mac` column, an HMAC under a subkey of the vault data key over
-- the columns that decide authority (see rowmac.py). Nullable: rows written before this release stay NULL until `pagerlens adopt-rowmacs`
-- signs them, and a NULL or wrong MAC is treated as a missing row only while the vault is unlocked. Sessions and API tokens get theirs from
-- the kit's own schema block.
ALTER TABLE llm_account ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE runbook     ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE app_setting ADD COLUMN IF NOT EXISTS mac text;
