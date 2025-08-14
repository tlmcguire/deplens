def delete_access_rule(rules, rule_id):
    del rules[rule_id]
    print(f"Access rule with ID {rule_id} has been deleted.")

access_rules = {
    'rule1': 'Application Credential 1',
    'rule2': 'Application Credential 2',
    'rule3': 'No Application Credential'
}

delete_access_rule(access_rules, 'non_existing_rule')