ALTER TABLE agents RENAME COLUMN compute_offering_requests_enabled TO escalation_requests_enabled;
ALTER TABLE compute_offering_requests RENAME TO escalation_requests;
ALTER TABLE escalation_requests ADD COLUMN command TEXT NOT NULL DEFAULT 'createServiceOffering';
ALTER TABLE escalation_requests ADD COLUMN description TEXT NOT NULL DEFAULT 'Legacy compute offering request';
ALTER TABLE escalation_requests ADD COLUMN reason TEXT NOT NULL DEFAULT 'Legacy owner assistance request';
INSERT OR IGNORE INTO platform_settings(name,value) VALUES('escalation_request_limit','3');
