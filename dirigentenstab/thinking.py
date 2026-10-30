"""Provider-advertised thinking controls and narrowly documented compatibility defaults."""

import re
from dataclasses import replace
from urllib.parse import urlsplit

from pydantic_ai.profiles.openai import OpenAIModelProfile, openai_model_profile
from pydantic_ai.providers.deepseek import DeepSeekProvider


LEVEL = re.compile(r'^[a-z][a-z0-9_-]{0,31}$')
OPENAI_RESPONSE_LEVELS = {
    'gpt-6-astra': ('low', 'medium', 'high', 'xhigh', 'max'),
    'gpt-6.1-sol': ('low', 'medium', 'high', 'xhigh', 'max'),
    'gpt-6-sol': ('none', 'low', 'medium', 'high', 'xhigh', 'max'),
    'gpt-6-luna': ('none', 'low', 'medium', 'high', 'xhigh', 'max'),
}
CHANNEL_THOUGHT = re.compile(r'<\|channel>thought.*?<channel\|>|<\|channel>(?:thought)?|<channel\|>', re.S)
TOOL_CALL = re.compile(r'<\|tool_?call>.*?(?:<tool_?call\|>|$)', re.S)


def visible_text(text):
    """Drop Gemma channel reasoning (`<|channel>thought ... <channel|>`), stray channel markers and tool-call markup
    (`<|toolcall>call:name{...}<toolcall|>`, or unterminated to the end)."""
    return TOOL_CALL.sub('', CHANNEL_THOUGHT.sub('', text)).strip()


def _deepseek(provider):
    return urlsplit(provider['base_url']).hostname == 'api.deepseek.com'


def _qwen(provider, model_id):
    name = model_id.lower()
    return (provider['protocol'] == 'chat' and re.search(r'(?:^|/)qwen3-\d+(?:\.\d+)?b(?:[-.]|$)', name)
            and not any(variant in name for variant in ('2507', 'thinking', 'instruct')))


def capabilities(provider, model_id, metadata=None):
    options = {'default': 'Model default'}
    effort = metadata.get('effort') if isinstance(metadata, dict) else None
    reported = effort.get('supported_levels') if isinstance(effort, dict) else None
    levels = ([level for level in reported if isinstance(level, str) and LEVEL.fullmatch(level)
               and level not in {'default', 'on', 'off'}] if isinstance(reported, list) and len(reported) <= 32 else [])
    if levels:
        if _deepseek(provider):
            options['off'] = 'Off'
        for level in levels:
            options['off' if level == 'none' else level] = 'Off' if level == 'none' else level.capitalize()
        return {'options': options, 'source': 'Levels advertised by the provider model API.'}
    if _deepseek(provider) and model_id in {'deepseek-flash', 'deepseek-v4-flash', 'deepseek-v4-pro'}:
        options.update(off='Off', on='On')
        return {'options': options, 'source': 'DeepSeek documents on/off thinking; this model API did not advertise effort levels.'}
    if _qwen(provider, model_id):
        options.update(off='Off', on='On')
        return {'options': options, 'source': 'Original hybrid Qwen3 supports an on/off chat-template switch; server support is required.'}
    if urlsplit(provider['base_url']).hostname == 'api.openai.com':
        model = re.sub(r'-\d{4}-\d{2}-\d{2}$', '', model_id)
        if provider['protocol'] == 'responses' and model in OPENAI_RESPONSE_LEVELS:
            levels = OPENAI_RESPONSE_LEVELS[model]
        elif model in {'o3', 'o3-mini', 'o4-mini'}:
            levels = ['low', 'medium', 'high']
        elif model in {'gpt-5', 'gpt-5-mini', 'gpt-5-nano'}:
            levels = ['minimal', 'low', 'medium', 'high']
        elif model == 'gpt-5.1':
            levels = ['none', 'low', 'medium', 'high']
        elif model == 'gpt-5.2':
            levels = ['none', 'low', 'medium', 'high', 'xhigh']
        if levels:
            options.update({'off' if level == 'none' else level: 'Off' if level == 'none' else level.capitalize()
                            for level in levels})
            return {'options': options, 'source': 'Documented OpenAI model levels; the model API did not advertise levels.'}
    return {'options': options, 'source': 'This model API did not advertise thinking controls.'}


def model_settings(provider, model_id, level):
    if level == 'default':
        return {}
    if not isinstance(level, str) or not LEVEL.fullmatch(level):
        raise ValueError('Invalid thinking level')
    if _deepseek(provider) and provider['protocol'] == 'chat':
        settings = {'extra_body': {'thinking': {'type': 'disabled' if level == 'off' else 'enabled'}}}
        if level not in {'off', 'on'}:
            settings['openai_reasoning_effort'] = level
        return settings
    if _qwen(provider, model_id) and level in {'on', 'off'}:
        return {'extra_body': {'chat_template_kwargs': {'enable_thinking': level == 'on'}}}
    if _deepseek(provider) and provider['protocol'] == 'responses' and level == 'on':
        return {'openai_reasoning_effort': 'high'}
    return {'openai_reasoning_effort': 'none' if level == 'off' else level}


def model_profile(provider, model_id):
    if _deepseek(provider) and provider['protocol'] == 'chat':
        profile = DeepSeekProvider.model_profile(model_id)
    elif urlsplit(provider['base_url']).hostname == 'api.openai.com':
        profile = openai_model_profile(model_id)
        model = re.sub(r'-\d{4}-\d{2}-\d{2}$', '', model_id)
        if provider['protocol'] == 'responses' and model in OPENAI_RESPONSE_LEVELS:
            profile = replace(profile, supports_thinking=True, openai_supports_reasoning=True,
                              openai_supports_encrypted_reasoning_content=True, openai_supports_phase=True,
                              thinking_always_enabled='none' not in OPENAI_RESPONSE_LEVELS[model],
                              openai_supports_reasoning_effort_none='none' in OPENAI_RESPONSE_LEVELS[model])
    else:
        profile = OpenAIModelProfile()
    return replace(profile, openai_supports_strict_tool_definition=False)
