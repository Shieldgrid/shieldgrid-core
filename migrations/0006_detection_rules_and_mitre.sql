-- Detection Rules & MITRE ATT&CK Catalog Schema
--

CREATE TABLE mitre_tactics (
    id          TEXT PRIMARY KEY, -- e.g. 'TA0001'
    name        TEXT NOT NULL,    -- e.g. 'Initial Access'
    description TEXT NOT NULL,
    sort_order  INT NOT NULL
);

CREATE TABLE mitre_techniques (
    id          TEXT PRIMARY KEY, -- e.g. 'T1059'
    name        TEXT NOT NULL,    -- e.g. 'Command and Scripting Interpreter'
    tactic_id   TEXT NOT NULL REFERENCES mitre_tactics(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    detection_count INT NOT NULL DEFAULT 0
);

CREATE TABLE detection_rules (
    id               UUID PRIMARY KEY,
    rule_id          TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL,
    severity         TEXT NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    category         TEXT NOT NULL,
    connector_id     TEXT NOT NULL,
    query_or_vql     TEXT NOT NULL,
    mitre_tactics    TEXT[] NOT NULL DEFAULT '{}',
    mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_detection_rules_connector ON detection_rules(connector_id);
CREATE INDEX idx_detection_rules_severity ON detection_rules(severity);
CREATE INDEX idx_detection_rules_enabled ON detection_rules(enabled);

-- Seed MITRE ATT&CK Tactics (Enterprise Matrix)
INSERT INTO mitre_tactics (id, name, description, sort_order) VALUES
('TA0043', 'Reconnaissance', 'Gathering information to plan future adversary operations.', 1),
('TA0042', 'Resource Development', 'Establishing resources they need to support operations.', 2),
('TA0001', 'Initial Access', 'Techniques that use various entry vectors to gain a foothold.', 3),
('TA0002', 'Execution', 'Techniques that result in adversary-controlled code running on a local or remote system.', 4),
('TA0003', 'Persistence', 'Techniques that adversaries use to keep access across restarts and changed credentials.', 5),
('TA0004', 'Privilege Escalation', 'Techniques to gain higher-level permissions on a system or network.', 6),
('TA0005', 'Defense Evasion', 'Techniques to avoid being detected throughout their compromise.', 7),
('TA0006', 'Credential Access', 'Techniques for stealing credentials like account names and passwords.', 8),
('TA0007', 'Discovery', 'Techniques to observe the system and gain knowledge about the environment.', 9),
('TA0008', 'Lateral Movement', 'Techniques to enter and control remote systems on a network.', 10),
('TA0009', 'Collection', 'Techniques to gather information and sources of information of interest.', 11),
('TA0011', 'Command and Control', 'Techniques to communicate with systems under adversary control.', 12),
('TA0010', 'Exfiltration', 'Techniques to steal data from your network.', 13),
('TA0040', 'Impact', 'Techniques to disrupt availability or compromise integrity of business systems.', 14)
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, sort_order = EXCLUDED.sort_order;

-- Seed MITRE ATT&CK Techniques
INSERT INTO mitre_techniques (id, name, tactic_id, description, detection_count) VALUES
('T1566', 'Phishing', 'TA0001', 'Spearphishing attachment, link, or voice/service vectors to gain initial access.', 4),
('T1190', 'Exploit Public-Facing Application', 'TA0001', 'Adversaries exploiting software vulnerabilities in internet-facing hosts.', 8),
('T1059', 'Command and Scripting Interpreter', 'TA0002', 'Adversaries executing commands via PowerShell, Bash, CMD, Python, or VBScript.', 19),
('T1053', 'Scheduled Task/Job', 'TA0003', 'Abusing task scheduling to execute programs periodically or on boot.', 7),
('T1547', 'Boot or Logon Autostart Execution', 'TA0003', 'Adversaries configuring system settings to automatically execute a program during boot or logon.', 11),
('T1078', 'Valid Accounts', 'TA0004', 'Adversaries obtaining and abusing credentials of existing accounts.', 14),
('T1055', 'Process Injection', 'TA0005', 'Injecting code into processes to evade defenses and run illicit operations.', 12),
('T1070', 'Indicator Removal', 'TA0005', 'Deleting logs, audit records, or history files to cover malicious activity.', 6),
('T1003', 'OS Credential Dumping', 'TA0006', 'Dumping credentials from LSASS memory, SAM database, or NTDS.dit.', 15),
('T1087', 'Account Discovery', 'TA0007', 'Enumerating local users or domain accounts across Active Directory.', 9),
('T1021', 'Remote Services', 'TA0008', 'Using SSH, RDP, SMB/Windows Admin Shares, or WinRM to move laterally.', 13),
('T1041', 'Exfiltration Over C2 Channel', 'TA0010', 'Stealing and packaging data over existing command and control channels.', 5),
('T1486', 'Data Encrypted for Impact', 'TA0040', 'Encrypting target files to disrupt availability and demand ransom payments.', 8)
ON CONFLICT (id) DO NOTHING;

-- Seed Core Detection Rules
INSERT INTO detection_rules (id, rule_id, name, description, severity, enabled, category, connector_id, query_or_vql, mitre_tactics, mitre_techniques) VALUES
(
    '22222222-2222-2222-2222-222222222201',
    'SHIELD-RULE-001',
    'LSASS Memory Dump Attempt Detected',
    'Detects access or handle acquisition of lsass.exe process by unauthorized binaries indicating Mimikatz or procdump execution.',
    'critical',
    TRUE,
    'Endpoint Security',
    'velociraptor',
    'SELECT * FROM Artifact.Windows.System.LSASSMemoryDump() WHERE Suspicious = TRUE',
    ARRAY['TA0006'],
    ARRAY['T1003']
),
(
    '22222222-2222-2222-2222-222222222202',
    'SHIELD-RULE-002',
    'Obfuscated PowerShell EncodedCommand Execution',
    'Detects invocation of powershell.exe with -enc, -EncodedCommand, or hidden base64 arguments.',
    'high',
    TRUE,
    'Process Monitoring',
    'velociraptor',
    'SELECT * FROM Artifact.Windows.System.ProcessExecution() WHERE CommandLine =~ "(?i)-enc(odedcommand)?"',
    ARRAY['TA0002', 'TA0005'],
    ARRAY['T1059', 'T1055']
),
(
    '22222222-2222-2222-2222-222222222203',
    'SHIELD-RULE-003',
    'Suspicious Scheduled Task Creation via Schtasks',
    'Detects creation of scheduled tasks executing from Temp, AppData, or Public directory paths.',
    'medium',
    TRUE,
    'Persistence',
    'wazuh',
    'rule.id: "60114" AND data.win.eventdata.commandLine: "*schtasks* /create *"',
    ARRAY['TA0003'],
    ARRAY['T1053']
),
(
    '22222222-2222-2222-2222-222222222204',
    'SHIELD-RULE-004',
    'Ransomware Volume Shadow Copy Deletion',
    'Detects vssadmin delete shadows or wmic shadowcopy delete command executions.',
    'critical',
    TRUE,
    'Impact & Recovery',
    'wazuh',
    'rule.id: "60100" AND (data.win.eventdata.commandLine: "*vssadmin*delete*shadows*" OR data.win.eventdata.commandLine: "*wmic*shadowcopy*delete*")',
    ARRAY['TA0040'],
    ARRAY['T1486']
),
(
    '22222222-2222-2222-2222-222222222205',
    'SHIELD-RULE-005',
    'Suspicious Remote RDP Session Creation',
    'Detects inbound RDP logon connections outside of business hours or from non-standard subnets.',
    'medium',
    TRUE,
    'Lateral Movement',
    'wazuh',
    'rule.id: "60106" AND data.win.system.eventID: "4624" AND data.win.eventdata.logonType: "10"',
    ARRAY['TA0008'],
    ARRAY['T1021']
)
ON CONFLICT (rule_id) DO NOTHING;
