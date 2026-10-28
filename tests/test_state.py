import pytest

from leash.contracts import ActionState
from leash.state import ActionLifecycle, InvalidTransition


def test_invalid_transition_is_rejected() -> None:
    lifecycle = ActionLifecycle()

    with pytest.raises(InvalidTransition, match="Invalid action transition"):
        lifecycle.transition(ActionState.EXECUTED)


def test_allow_lifecycle_reaches_executed() -> None:
    lifecycle = ActionLifecycle()

    for state in (
        ActionState.PREVIEWED,
        ActionState.DECIDED,
        ActionState.AUTHORIZED,
        ActionState.EXECUTING,
        ActionState.EXECUTED,
    ):
        lifecycle.transition(state)

    assert lifecycle.state == ActionState.EXECUTED
