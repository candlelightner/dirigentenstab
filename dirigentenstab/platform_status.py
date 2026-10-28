import json
import time

STALE_SECONDS = 300


def read(path, now=None):
    """Parsed host watchdog status plus `stale`, or None when missing/invalid. Never raises."""
    try:
        with open(path, encoding='utf-8') as file:
            status = json.load(file)
        if not isinstance(status, dict):
            return None
        return {**status, 'stale': (time.time() if now is None else now) - float(status['updated']) > STALE_SECONDS}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def refusal(status):
    """Message for the first host that is not Up in a fresh status, else None."""
    if not status or status['stale']:
        return None
    try:
        for host in status.get('hosts') or []:
            if host.get('status') != 'Up':
                since = time.strftime('%H:%M', time.localtime(host['since']))
                return (f"CloudStack host {host.get('name')} is {host.get('status')} since {since}; managed deployment "
                        'refused before dispatch. Check platform_status and retry once the host is Up.')
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, OSError):
        return None


def banner(status):
    """(text, unhealthy) for the owner banner, or None when nothing should be shown."""
    if not status:
        return None
    if status['stale']:
        return 'Platform status unavailable', False
    if status.get('healthy') is False:
        return '\n'.join(str(i) for i in (status.get('issues') or [])[:5]) or 'Platform unhealthy', True


def summary(status):
    """Agent-facing view: no owner-only `actions`, issues capped."""
    if not status:
        return {'status': 'unknown', 'detail': 'Platform status feed is unavailable; this is not proof of an outage.'}
    issues = [str(i)[:200] for i in (status.get('issues') or [])]
    return {**{k: v for k, v in status.items() if k not in {'actions', 'issues'}},
            'issues': issues[:5] + ([f'... and {len(issues) - 5} more'] if len(issues) > 5 else [])}
