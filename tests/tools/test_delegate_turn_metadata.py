"""Turn metadata must stop at delegated child model-turn boundaries."""

from hermes_cli import plugins
from hermes_cli.plugins import PluginContext, PluginManifest, PluginManager
from hermes_cli.turn_context import (
    _bind_turn_metadata,
    _reset_turn_metadata,
    get_turn_metadata,
)
from tools.delegate_tool import _run_single_child


class _Parent:
    _current_task_id = None

    def _touch_activity(self, _description):
        return None


class _Child:
    tool_progress_callback = None
    _delegate_saved_tool_names = []
    _credential_pool = None
    _subagent_id = None
    _delegate_depth = 1
    _parent_subagent_id = None
    model = "test-model"
    session_id = "child-session"
    session_prompt_tokens = 0
    session_completion_tokens = 0
    session_estimated_cost_usd = 0.0
    session_reasoning_tokens = 0

    def get_activity_summary(self):
        return {"api_call_count": 1, "max_iterations": 1, "current_tool": None}

    def run_conversation(self, user_message, task_id=None, **_kwargs):
        plugins.invoke_hook(
            "pre_llm_call",
            session_id=self.session_id,
            user_message=user_message,
            turn_id=task_id,
        )
        return {
            "final_response": "done",
            "completed": True,
            "api_calls": 1,
            "messages": [],
        }

    def close(self):
        return None


def test_delegate_child_pre_llm_hook_does_not_inherit_parent_turn_metadata(
    monkeypatch,
):
    manager = PluginManager()
    plugin_context = PluginContext(
        PluginManifest(name="turn-scope-test", source="test", key="turn-scope-test"),
        manager,
    )
    observed = []
    plugin_context.register_hook(
        "pre_llm_call",
        lambda **_kwargs: observed.append(get_turn_metadata()),
    )
    monkeypatch.setattr(plugins, "_plugin_manager", manager)

    binding = _bind_turn_metadata({"acme.review": {"mode": "strict"}})
    try:
        result = _run_single_child(0, "inspect", _Child(), _Parent())
        assert get_turn_metadata() == {"acme.review": {"mode": "strict"}}
    finally:
        _reset_turn_metadata(binding)

    assert result["status"] == "completed"
    assert observed == [{}]
