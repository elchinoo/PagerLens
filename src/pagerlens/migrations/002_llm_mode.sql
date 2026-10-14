-- LLM and hybrid investigations: which method produced each hypothesis, and each method's own score.
ALTER TABLE run DROP CONSTRAINT run_mode_check;
ALTER TABLE run ADD CONSTRAINT run_mode_check CHECK (mode IN ('rules', 'llm', 'hybrid'));

ALTER TABLE hypothesis
    ADD COLUMN source text NOT NULL DEFAULT 'rules' CHECK (source IN ('rules', 'llm', 'both')),
    ADD COLUMN rules_score real,
    ADD COLUMN llm_score real,
    ADD COLUMN grounded boolean;     -- llm/both: did the model cite at least one real observation?

ALTER TABLE run ADD COLUMN warning text;   -- a non-fatal problem, e.g. the AI step failed but rules results stand
