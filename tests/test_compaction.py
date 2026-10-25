import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from pydantic_ai import Agent, capture_run_messages
from pydantic_ai.messages import (
    InstructionPart, ModelMessagesTypeAdapter, ModelRequest, ModelResponse, SystemPromptPart,
    TextPart, ToolCallPart, ToolReturnPart, UserPromptPart,
)
from pydantic_ai.models import ModelRequestParameters
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.tools import ToolDefinition

from dirigentenstab.compaction import CompactionModel, estimate_tokens
from dirigentenstab.store import Store


@pytest.fixture
def history():
    return [ModelRequest(parts=[SystemPromptPart('Exact system boundary')]),
            ModelRequest(parts=[UserPromptPart('Old task')]),
            ModelResponse(parts=[TextPart('Old factual activity and completed resource IDs. ' * 500)]),
            ModelRequest(parts=[UserPromptPart('Exact current task')]),
            ModelResponse(parts=[ToolCallPart('inspect', {}, tool_call_id='recent')]),
            ModelRequest(parts=[ToolReturnPart('inspect', 'Exact recent result', tool_call_id='recent')])]


@pytest.fixture
def store(tmp_path, history):
    key = tmp_path / 'master'
    key.write_bytes(Fernet.generate_key())
    store = Store(str(tmp_path / 'state.db'), str(key))
    store.execute('INSERT INTO agents(id,name,domain_id,account_id,user_id,credentials) VALUES(?,?,?,?,?,?)',
                  ('agent', 'Agent', 'domain', 'account', 'user', store.seal({})))
    store.execute('INSERT INTO conversations(id,agent_id,human_id,title,created,messages) VALUES(?,?,?,?,?,?)',
                  ('conversation', 'agent', 'human', 'Task', 1,
                   store.seal(json.loads(ModelMessagesTypeAdapter.dump_json(history)))))
    return store


def engine(store, history, **options):
    state = SimpleNamespace(main=[], summaries=[], events=[])

    def main(messages, info):
        state.main.append(messages)
        return ModelResponse(parts=[TextPart('Main answer')])

    def summary(messages, info):
        state.summaries.append(messages)
        assert info.function_tools == [] and info.output_tools == []
        assert info.model_settings['max_tokens'] == 4096 and info.model_settings['timeout'] == 60
        return ModelResponse(parts=[TextPart('Resource IDs retained; completed work must not be repeated.')])

    async def emit(event):
        state.events.append(event)

    kwargs = {'store': store, 'conversation_id': 'conversation', 'summary_model': FunctionModel(summary),
              'context_window': estimate_tokens(history, ModelRequestParameters()) + 500,
              'threshold_percent': 50, 'response_reserve': 500, 'on_event': emit}
    kwargs.update(options)
    return CompactionModel(FunctionModel(main), **kwargs), state


async def test_compaction_changes_provider_view_only_and_pins_exact_current_context(store, history):
    wrapper, state = engine(store, history)
    archived = store.one('SELECT messages FROM conversations')['messages']
    original = ModelMessagesTypeAdapter.dump_json(history)
    parameters = ModelRequestParameters(instruction_parts=[InstructionPart(content='Current agent instructions')])
    await wrapper.request(history, None, parameters)
    assert len(state.main) == len(state.summaries) == 1
    sent = state.main[0]
    assert sent is not history and ModelMessagesTypeAdapter.dump_json(history) == original
    assert store.one('SELECT messages FROM conversations')['messages'] == archived
    assert sent[0].parts[0] is history[0].parts[0]
    assert any(part is history[3].parts[0] for message in sent for part in message.parts)
    assert sent[-2:] == history[-2:]
    summary_part = next(part for message in sent for part in message.parts
                        if isinstance(part, UserPromptPart) and 'conversation_summary' in str(part.content))
    assert 'not a new request or instructions' in summary_part.content
    row = store.one('SELECT * FROM conversation_compactions')
    assert row['covered_messages'] == 4
    assert b'Resource IDs retained' not in row['summary']
    assert 'Resource IDs retained' in store.open(row['summary'])
    usage = [event['context'] for event in state.events if event['type'] == 'context_usage']
    assert usage[-1]['estimated_tokens'] < usage[0]['estimated_tokens']
    assert 'Estimated' in usage[-1]['source']
    assert [event['phase'] for event in state.events if event['type'] == 'compaction'] == ['started', 'completed']
    assert 'Resource IDs retained' not in str(state.events)


async def test_summary_reuse_is_persistent_and_hash_mismatch_falls_back_to_full_history(store, history):
    wrapper, state = engine(store, history)
    parameters = ModelRequestParameters()
    await wrapper.request(history, None, parameters)
    saved = store.one('SELECT * FROM conversation_compactions')
    restored = ModelMessagesTypeAdapter.validate_python(store.open(store.one('SELECT messages FROM conversations')['messages']))
    restarted, next_state = engine(store, restored)
    await restarted.request(restored, None, parameters)
    assert next_state.summaries == []
    assert next_state.main[0][1].parts[0].content == state.main[0][1].parts[0].content
    history[2] = ModelResponse(parts=[TextPart('Unrelated replacement message')])
    restarted.context_window = 100000
    await restarted.request(history, None, parameters)
    assert next_state.main[-1] is history and next_state.summaries == []
    assert store.one('SELECT * FROM conversation_compactions') == saved


async def test_single_long_user_turn_compacts_complete_tools_and_keeps_recent_and_pending_parts(store):
    history = [ModelRequest(parts=[SystemPromptPart('System'), UserPromptPart('Keep this exact task')]),
               ModelResponse(parts=[ToolCallPart('inspect', {}, tool_call_id='old')]),
               ModelRequest(parts=[ToolReturnPart('inspect', 'Old large result ' * 2000, tool_call_id='old')]),
               ModelResponse(parts=[ToolCallPart('inspect', {}, tool_call_id='recent')]),
               ModelRequest(parts=[ToolReturnPart('inspect', 'Recent exact result', tool_call_id='recent')]),
               ModelResponse(parts=[ToolCallPart('inspect', {}, tool_call_id='pending')])]
    wrapper, state = engine(store, history)
    await wrapper.request(history, None, ModelRequestParameters())
    assert store.one('SELECT covered_messages FROM conversation_compactions')['covered_messages'] == 3
    sent = state.main[0]
    assert sent[-3:] == history[-3:]
    assert any(part is history[0].parts[1] for message in sent for part in message.parts)
    pending = set()
    for message in sent:
        for part in message.parts:
            if isinstance(part, ToolCallPart):
                pending.add(part.tool_call_id)
            elif isinstance(part, ToolReturnPart):
                assert part.tool_call_id in pending
                pending.remove(part.tool_call_id)
    assert pending == {'pending'}


@pytest.mark.parametrize('at_boundary', [False, True])
async def test_threshold_uses_usable_input_budget_and_triggers_at_equality(store, history, at_boundary):
    estimated = estimate_tokens(history, ModelRequestParameters())
    usable = estimated * 100 + (0 if at_boundary else 1)
    wrapper, state = engine(store, history, context_window=usable + 1, response_reserve=1, threshold_percent=1)
    await wrapper.request(history, None, ModelRequestParameters())
    assert bool(state.summaries) == at_boundary
    usage = state.events[0]['context']
    assert usage['usable_tokens'] == usable and usage['response_reserve'] == 1


async def test_estimate_includes_instructions_and_tool_schema_metadata(history):
    bare = estimate_tokens(history, ModelRequestParameters())
    parameters = ModelRequestParameters(instruction_parts=[InstructionPart(content='Instructions ' * 1000)],
        function_tools=[ToolDefinition(name='inspect', parameters_json_schema={
            'type': 'object', 'properties': {'value': {'type': 'string', 'description': 'Tool details ' * 1000}}})])
    assert estimate_tokens(history, parameters) > bare + 3000


@pytest.mark.parametrize('window', [None, 100000])
async def test_disabled_compaction_passes_original_history_without_using_summary_model(store, history, window):
    wrapper, state = engine(store, history, threshold_percent=None, context_window=window, summary_model=None)
    await wrapper.request(history, None, ModelRequestParameters())
    assert state.main[0] is history and state.summaries == []
    assert store.one('SELECT * FROM conversation_compactions') is None
    assert state.events[0]['context']['context_window'] == window


async def test_unknown_window_fails_clearly_when_compaction_is_enabled(store, history):
    wrapper, state = engine(store, history, context_window=None)
    with pytest.raises(ValueError, match='known context window'):
        await wrapper.request(history, None, ModelRequestParameters())
    assert not state.main and not state.summaries
    assert state.events[0]['context']['percent'] is None


async def test_pending_mutations_block_new_compaction_without_changing_archive(store, history):
    wrapper, state = engine(store, history, pending=lambda: True, context_window=1000)
    archived = store.one('SELECT messages FROM conversations')['messages']
    with pytest.raises(ValueError, match='reconciliation'):
        await wrapper.request(history, None, ModelRequestParameters())
    assert not state.main and not state.summaries
    assert store.one('SELECT messages FROM conversations')['messages'] == archived
    assert store.one('SELECT * FROM conversation_compactions') is None


@pytest.mark.parametrize('failure', ['request', 'no-shrink', 'cannot-fit', 'tool-attempt'])
async def test_failed_compaction_preserves_archive_and_never_calls_main_model(store, history, failure):
    calls = []

    def summary(messages, info):
        calls.append(messages)
        if failure == 'request':
            raise RuntimeError('Remote response containing private credentials')
        if failure == 'tool-attempt':
            return ModelResponse(parts=[ToolCallPart('unsafe', {}, tool_call_id='not-allowed')])
        return ModelResponse(parts=[TextPart('Too large ' * 20000 if failure == 'no-shrink' else 'Short summary')])

    wrapper, state = engine(store, history, summary_model=FunctionModel(summary))
    if failure == 'cannot-fit':
        history[3] = ModelRequest(parts=[UserPromptPart('Current request ' * 3000)])
        wrapper.context_window = 1000
    archived = store.one('SELECT messages FROM conversations')['messages']
    with pytest.raises((ValueError, RuntimeError), match='preserved') as error:
        await wrapper.request(history, None, ModelRequestParameters())
    assert len(calls) == 1 and state.main == []
    assert 'private credentials' not in str(error.value)
    assert [event['phase'] for event in state.events if event['type'] == 'compaction'] == ['started', 'failed']
    assert store.one('SELECT messages FROM conversations')['messages'] == archived
    assert store.one('SELECT * FROM conversation_compactions') is None


async def test_failed_extension_keeps_previous_valid_summary(store, history):
    wrapper, _ = engine(store, history)
    parameters = ModelRequestParameters()
    await wrapper.request(history, None, parameters)
    saved = store.one('SELECT * FROM conversation_compactions')
    history.extend([ModelResponse(parts=[TextPart('New large activity ' * 2000)]),
                    ModelRequest(parts=[UserPromptPart('Next exact question')]),
                    ModelResponse(parts=[TextPart('Newest answer')]),
                    ModelRequest(parts=[UserPromptPart('Continue')])])

    def fail(messages, info):
        raise RuntimeError('Unavailable compaction model')

    wrapper.summary_model = FunctionModel(fail)
    with pytest.raises(RuntimeError, match='previous summary are preserved'):
        await wrapper.request(history, None, parameters)
    assert store.one('SELECT * FROM conversation_compactions') == saved


async def test_unshrinkable_current_tool_exchange_fails_before_summary_request(store):
    history = [ModelRequest(parts=[UserPromptPart('Current task')]),
               ModelResponse(parts=[ToolCallPart('inspect', {}, tool_call_id='current')]),
               ModelRequest(parts=[ToolReturnPart('inspect', 'Huge current result ' * 3000, tool_call_id='current')])]
    wrapper, state = engine(store, history, context_window=1000)
    with pytest.raises(ValueError, match='preserving the current user request'):
        await wrapper.request(history, None, ModelRequestParameters())
    assert not state.main and not state.summaries


async def test_unsafe_persisted_tool_boundary_is_not_reused(store, history):
    covered = 5
    digest = hashlib.sha256(ModelMessagesTypeAdapter.dump_json(history[:covered])).hexdigest()
    store.execute('INSERT INTO conversation_compactions VALUES(?,?,?,?,?)',
                  ('conversation', covered, digest, store.seal('Unsafe summary'), 1))
    wrapper, state = engine(store, history, context_window=100000)
    await wrapper.request(history, None, ModelRequestParameters())
    assert state.main[0] is history and not state.summaries


async def test_streaming_uses_compacted_view_without_rewriting_original_messages(store, history):
    observed = []

    async def stream(messages, info):
        observed.append(messages)
        yield 'Streamed answer'

    wrapper, _ = engine(store, history)
    wrapper.wrapped = FunctionModel(stream_function=stream)
    original = ModelMessagesTypeAdapter.dump_json(history)
    async with wrapper.request_stream(history, None, ModelRequestParameters()) as response:
        async for _ in response:
            pass
        assert response.get().parts[0].content == 'Streamed answer'
    assert observed[0] is not history and observed[0][-2:] == history[-2:]
    assert ModelMessagesTypeAdapter.dump_json(history) == original


async def test_stop_cancellation_during_summary_propagates_and_commits_nothing(store, history):
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def summary(messages, info):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    wrapper, state = engine(store, history, summary_model=FunctionModel(summary))
    task = asyncio.create_task(wrapper.request(history, None, ModelRequestParameters()))
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set() and not state.main
    assert store.one('SELECT * FROM conversation_compactions') is None


async def test_actual_streamed_agent_keeps_full_capture_and_reuses_summary_after_archive_reload(store, history):
    wrapper, state = engine(store, history)
    forwarded = []

    async def main(messages, info):
        forwarded.append(messages)
        yield 'Main answer'

    async def consume(ctx, events):
        async for _ in events:
            pass

    wrapper.wrapped = FunctionModel(stream_function=main)
    with capture_run_messages() as captured:
        first = await Agent(wrapper).run('New current request', message_history=history, event_stream_handler=consume)
        assert 'Old factual activity' in str(captured)
        assert 'previous_summary' not in str(captured)
    assert len(state.summaries) == 1 and 'Old factual activity' not in str(forwarded[0])
    archived = json.loads(ModelMessagesTypeAdapter.dump_json(first.all_messages()))
    store.execute('UPDATE conversations SET messages=?', (store.seal(archived),))
    saved_row = store.one('SELECT * FROM conversation_compactions')
    restored = ModelMessagesTypeAdapter.validate_python(store.open(store.one('SELECT messages FROM conversations')['messages']))
    restarted, next_state = engine(store, restored)
    restarted.wrapped = FunctionModel(stream_function=main)
    await Agent(restarted).run('Another current request', message_history=restored, event_stream_handler=consume)
    assert not next_state.summaries and store.one('SELECT * FROM conversation_compactions') == saved_row
    assert 'Old factual activity' not in str(forwarded[1])
    assert 'New current request' in str(forwarded[1]) and 'Another current request' in str(forwarded[1])


async def test_low_threshold_reuses_fitting_summary_when_no_new_prefix_can_be_compacted(store, history):
    wrapper, state = engine(store, history, threshold_percent=1)
    parameters = ModelRequestParameters()
    await wrapper.request(history, None, parameters)
    saved = store.one('SELECT * FROM conversation_compactions')
    assert state.events[-1]['context']['percent'] > 1
    await wrapper.request(history, None, parameters)
    assert len(state.main) == 2 and len(state.summaries) == 1
    assert store.one('SELECT * FROM conversation_compactions') == saved
    assert state.events[-1]['phase'] == 'skipped'


async def test_first_prompt_above_low_threshold_but_within_window_is_preserved(store):
    history = [ModelRequest(parts=[SystemPromptPart('System instructions'), UserPromptPart('Current task ' * 100)])]
    wrapper, state = engine(store, history, threshold_percent=1)
    await wrapper.request(history, None, ModelRequestParameters())
    assert state.main[0] is history and not state.summaries
    assert state.events[0]['context']['percent'] > 1
    assert state.events[-1]['phase'] == 'skipped'
    assert store.one('SELECT * FROM conversation_compactions') is None


async def test_pending_operations_do_not_force_compaction_of_an_already_fitting_view(store, history):
    wrapper, state = engine(store, history, pending=lambda: True)
    await wrapper.request(history, None, ModelRequestParameters())
    assert state.main[0] is history and not state.summaries
    assert store.one('SELECT * FROM conversation_compactions') is None


async def test_same_small_context_model_uses_reserved_output_budget_for_summary(store, history):
    limits = []

    def shared(messages, info):
        if info.instructions and info.instructions.startswith('Summarize the supplied conversation data'):
            limits.append(info.model_settings['max_tokens'])
            return ModelResponse(parts=[TextPart('Concise summary')])
        return ModelResponse(parts=[TextPart('Main answer')])

    shared_model = FunctionModel(shared)
    wrapper = CompactionModel(shared_model, store=store, conversation_id='conversation', summary_model=shared_model,
                              context_window=8192, threshold_percent=50, response_reserve=2048)
    await wrapper.request(history, None, ModelRequestParameters())
    assert limits == [2048]
