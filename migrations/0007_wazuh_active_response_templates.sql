-- Wazuh Active Response Action Templates
-- 
-- Adds specific Wazuh AR command templates for network containment,
-- process termination, and custom script execution.

INSERT INTO action_templates (id, name, display_name, description, category, provider, risk_level, params_schema)
VALUES
    -- Network containment
    ('22222222-2222-2222-2222-222222222201', 'wazuh_firewall_drop', 'Wazuh Firewall Drop', 'Block an IP address using the host firewall via Wazuh active response.', 'containment', 'wazuh', 'high', '{"agent_id": {"type": "string", "required": true}, "ip": {"type": "string", "required": true}}'::jsonb),
    ('22222222-2222-2222-2222-222222222202', 'wazuh_firewall_allow', 'Wazuh Firewall Allow', 'Remove an IP block rule from the host firewall via Wazuh active response.', 'containment', 'wazuh', 'medium', '{"agent_id": {"type": "string", "required": true}, "ip": {"type": "string", "required": true}}'::jsonb),
    
    -- Windows-specific
    ('22222222-2222-2222-2222-222222222203', 'wazuh_netsh_block_ip', 'Wazuh Netsh Block IP', 'Block an IP address using Windows Firewall via netsh command.', 'containment', 'wazuh', 'high', '{"agent_id": {"type": "string", "required": true}, "ip": {"type": "string", "required": true}}'::jsonb),
    ('22222222-2222-2222-2222-222222222204', 'wazuh_netsh_delete_rule', 'Wazuh Netsh Delete Rule', 'Remove a Windows Firewall rule by name.', 'remediation', 'wazuh', 'medium', '{"agent_id": {"type": "string", "required": true}, "rule_name": {"type": "string", "required": true}}'::jsonb),
    
    -- Process control
    ('22222222-2222-2222-2222-222222222205', 'wazuh_kill_process', 'Wazuh Kill Process', 'Terminate a process by name or PID on the target agent.', 'remediation', 'wazuh', 'medium', '{"agent_id": {"type": "string", "required": true}, "process_name": {"type": "string", "required": false}, "pid": {"type": "number", "required": false}}'::jsonb),
    
    -- Custom scripts
    ('22222222-2222-2222-2222-222222222206', 'wazuh_custom_script', 'Wazuh Custom Script', 'Execute a custom active response script on the target agent.', 'forensics', 'wazuh', 'high', '{"agent_id": {"type": "string", "required": true}, "script_name": {"type": "string", "required": true}, "args": {"type": "string", "required": false}}'::jsonb),
    
    -- DNS containment
    ('22222222-2222-2222-2222-222222222207', 'wazuh_dns_block', 'Wazuh DNS Block', 'Block DNS resolution for a domain by modifying the hosts file.', 'containment', 'wazuh', 'high', '{"agent_id": {"type": "string", "required": true}, "domain": {"type": "string", "required": true}}'::jsonb)

ON CONFLICT (name) DO NOTHING;
