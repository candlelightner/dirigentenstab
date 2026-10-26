from dirigentenstab.web import history_parts


def test_history_parts_yields_pause_work_reason_as_agent_message():
    history = {'messages': [
        {'kind': 'request', 'parts': [{'part_kind': 'user-prompt', 'content': 'Inspect guest'}]},
        {'kind': 'response', 'parts': [
            {'part_kind': 'tool-call', 'tool_name': 'pause_work', 'tool_call_id': 'call-1',
             'args': {'reason': 'Need the owner to provide a guest credential'}},
        ]},
    ]}
    parts = list(history_parts(history))
    assert parts == [
        ('human', 'Inspect guest'),
        ('activity', {'type': 'tool_call', 'name': 'pause_work', 'call_id': 'call-1',
                      'content': {'reason': 'Need the owner to provide a guest credential'}}),
        ('agent', 'Need the owner to provide a guest credential'),
    ]

    history_json_str = {
        'messages': [
            {'kind': 'request', 'parts': [{'part_kind': 'user-prompt', 'content': 'Resume'}]},
            {'kind': 'response', 'parts': [
                {'part_kind': 'tool-call', 'tool_name': 'pause_work', 'tool_call_id': 'call-2',
                 'args': '{"reason": "Need SSH key"}'},
            ]},
        ],
        'runs': [{'events': [
            {'type': 'tool_call', 'name': 'pause_work', 'call_id': 'call-2',
             'content': {'reason': 'Need SSH key'}},
        ]}],
    }
    parts = list(history_parts(history_json_str))
    assert parts[-1] == ('agent', 'Need SSH key')
    assert parts.count(('agent', 'Need SSH key')) == 1

    history_saved_only = {
        'runs': [{'events': [
            {'type': 'tool_call', 'name': 'pause_work', 'call_id': 'call-3',
             'content': {'reason': 'Legacy event pause'}},
        ]}],
    }
    assert list(history_parts(history_saved_only))[-1] == ('agent', 'Legacy event pause')
