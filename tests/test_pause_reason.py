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


def test_escalation_notices_are_placed_after_their_request_activity():
    from dirigentenstab.web_chat import with_escalation_notices

    def call(op, cid):
        return ('activity', {'type': 'tool_call', 'operation_id': op, 'call_id': cid})

    parts = [('human', 'hi'), call('r1', 'a'), call('r1', 'b'), ('agent', 'one'), call('r2', 'c'), ('agent', 'two')]
    requests = [
        {'id': 'e1', 'run_id': 'r1', 'call_id': 'a', 'status': 'deferred'},
        {'id': 'e2', 'run_id': 'r2', 'call_id': 'c', 'status': 'approved'},
        {'id': 'e3', 'run_id': 'r1', 'call_id': 'a', 'status': 'approved'},
        {'id': 'e4', 'run_id': 'r1', 'call_id': 'zz', 'status': 'uncertain'},
        {'id': 'e5', 'run_id': 'r1', 'call_id': 'a', 'status': 'pending'},
        {'id': 'e6', 'run_id': 'gone', 'call_id': 'a', 'status': 'failed'},
    ]
    placed = [(content if kind == 'notice' else kind, key) for kind, content, key in with_escalation_notices(parts, requests)]
    assert placed == [
        ('human', None), ('activity', None),
        ('Escalation declined', ('escalation', 'e1')), ('Escalation approved', ('escalation', 'e3')),
        ('activity', None), ('Escalation approved, outcome uncertain', ('escalation', 'e4')),
        ('agent', None), ('activity', None), ('Escalation approved', ('escalation', 'e2')), ('agent', None),
        ('Escalation approved, but the command failed', ('escalation', 'e6')),
    ]


def test_history_parts_strips_gemma_channel_thought_and_skips_empty_bubbles():
    def reply(*texts):
        return {'messages': [{'kind': 'response', 'parts': [{'part_kind': 'text', 'content': t} for t in texts]}]}

    assert list(history_parts(reply('<|channel>thought\n<channel|>', '<|channel>thought'))) == []
    assert list(history_parts(reply('<|channel>thought\nPlan the call.<channel|>Done.'))) == [('agent', 'Done.')]
    assert list(history_parts(reply('<|channel>thought\nFinal answer'))) == [('agent', 'Final answer')]
    assert list(history_parts(reply('<|channel>Done.'))) == [('agent', 'Done.')]
