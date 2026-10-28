from __future__ import annotations

from dataclasses import dataclass

from leash.contracts import ActionState


class InvalidTransition(ValueError):
    pass


_ALLOWED_TRANSITIONS: dict[ActionState, frozenset[ActionState]] = {
    ActionState.PROPOSED: frozenset({ActionState.PREVIEWED}),
    ActionState.PREVIEWED: frozenset({ActionState.DECIDED}),
    ActionState.DECIDED: frozenset(
        {ActionState.AUTHORIZED, ActionState.REVIEW_PENDING, ActionState.BLOCKED}
    ),
    ActionState.AUTHORIZED: frozenset({ActionState.EXECUTING}),
    ActionState.REVIEW_PENDING: frozenset({ActionState.AUTHORIZED, ActionState.BLOCKED}),
    ActionState.EXECUTING: frozenset({ActionState.EXECUTED, ActionState.FAILED}),
    ActionState.BLOCKED: frozenset(),
    ActionState.EXECUTED: frozenset(),
    ActionState.FAILED: frozenset(),
}


@dataclass
class ActionLifecycle:
    state: ActionState = ActionState.PROPOSED

    def transition(self, target: ActionState) -> None:
        if target not in _ALLOWED_TRANSITIONS[self.state]:
            raise InvalidTransition(f"Invalid action transition: {self.state} -> {target}")
        self.state = target
