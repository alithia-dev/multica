ALTER TABLE issue DROP CONSTRAINT issue_creator_type_check;
ALTER TABLE issue ADD CONSTRAINT issue_creator_type_check CHECK (creator_type IN ('member', 'agent'));
ALTER TABLE comment DROP CONSTRAINT comment_author_type_check;
ALTER TABLE comment ADD CONSTRAINT comment_author_type_check CHECK (author_type IN ('member', 'agent', 'system'));
ALTER TABLE activity_log DROP CONSTRAINT activity_log_actor_type_check;
ALTER TABLE activity_log ADD CONSTRAINT activity_log_actor_type_check CHECK (actor_type IN ('member', 'agent', 'system'));
DROP TABLE service_account_token;
DROP TABLE service_account;
