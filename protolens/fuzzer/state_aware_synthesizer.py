from __future__ import annotations

from collections import defaultdict
from typing import Any

from protolens.fsm.fsm_model import Conflict, PlannedStatePath, SeedIntent, stable_id


class StateAwareTestSynthesizer:
    """Expand shortest FSM paths into auditable seed families."""

    def synthesize(
        self,
        planned_paths: list[PlannedStatePath],
        conflicts: list[Conflict],
        protocol: str,
    ) -> list[SeedIntent]:
        conflict_index = {conflict.id: conflict for conflict in conflicts}
        counters: dict[str, int] = defaultdict(int)
        intents: list[SeedIntent] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()
        for path_index, path in enumerate(planned_paths):
            if not path.reachable or not path.messages:
                continue
            conflict = conflict_index.get(path.conflict_id)
            family_id = stable_id("family", path.conflict_id)
            for variant in _variants_for_path(path, conflict, protocol):
                messages = _clean_messages(variant["messages"])
                if not messages:
                    continue
                key = (path.conflict_id, tuple(_canonical_message(item) for item in messages))
                if key in seen:
                    continue
                seen.add(key)
                counters[path.conflict_id] += 1
                variant_name = str(variant["variant"])
                seed_id = stable_id("seed", path.conflict_id, f"{counters[path.conflict_id]:03d}", variant_name)
                intents.append(
                    SeedIntent(
                        seed_id=seed_id,
                        conflict_id=path.conflict_id,
                        family_id=family_id,
                        variant=variant_name,
                        objective=str(variant["objective"]),
                        states=list(path.states),
                        messages=messages,
                        mutation_points=list(variant.get("mutation_points", path.mutation_points)),
                        required_guards=list(path.required_guards),
                        expected_feedback=list(variant.get("expected_feedback", [])),
                        priority=_priority(conflict, path, variant_name),
                        reachable=True,
                        reason=str(variant.get("reason", "")),
                        source_path_index=path_index,
                        source_candidate_id=path.candidate_id,
                    )
                )
        return intents


def _variants_for_path(path: PlannedStatePath, conflict: Conflict | None, protocol: str) -> list[dict[str, Any]]:
    messages = _clean_messages(path.messages)
    variants: list[dict[str, Any]] = [
        {
            "variant": "baseline_valid_prefix",
            "objective": "Probe the selected candidate sequence; response acceptance does not prove hidden state.",
            "messages": messages,
            "mutation_points": path.mutation_points,
            "expected_feedback": ["queue_match", "ipsm_state_match"],
            "reason": "baseline calibration: " + str(path.calibration.get("status", "candidate")),
        }
    ]
    if not messages:
        return variants

    last_index = _last_mutation_index(path, messages)
    guards = " ".join(path.required_guards + ([conflict.description] if conflict else [])).lower()

    direct = _direct_trigger_messages(path, conflict, messages)
    if direct:
        variants.append(
            {
                "variant": "direct_divergent_trigger",
                "objective": "Exercise the disputed transition as early as possible.",
                "messages": direct,
                "mutation_points": [max(0, len(direct) - 1)],
                "expected_feedback": ["new_path_or_rejection_boundary"],
                "reason": "direct transition probe derived from conflict label",
            }
        )

    missing_guard = _missing_guard_messages(messages, guards, protocol, last_index)
    if missing_guard:
        variants.append(
            {
                "variant": "missing_guard_material",
                "objective": "Reach the boundary while omitting guard material expected by the specification.",
                "messages": missing_guard,
                "mutation_points": list(range(max(0, len(missing_guard) - 2), len(missing_guard))),
                "expected_feedback": ["guard_rejection", "unexpected_state_advance"],
                "reason": "remove authentication, session, or transport prerequisites near the guarded edge",
            }
        )

    stale = _stale_guard_messages(messages, guards, protocol, last_index)
    if stale:
        variants.append(
            {
                "variant": "stale_session_value",
                "objective": "Check whether stale or invalid guard-bearing state is accepted.",
                "messages": stale,
                "mutation_points": [last_index],
                "expected_feedback": ["guard_rejection", "unexpected_acceptance"],
                "reason": "substitute stale session/authentication material",
            }
        )

    malformed = _malformed_guard_messages(messages, guards, protocol, last_index)
    if malformed:
        variants.append(
            {
                "variant": "malformed_guard_field",
                "objective": "Stress parser recovery at guard-bearing fields.",
                "messages": malformed,
                "mutation_points": [last_index],
                "expected_feedback": ["parser_error", "state_desynchronization"],
                "reason": "malform the field most likely to guard the transition",
            }
        )

    if len(messages) >= 2:
        variants.append(
            {
                "variant": "wrong_message_order",
                "objective": "Verify that the implementation rejects the target command before prerequisites.",
                "messages": [messages[-1], *messages[:-1]],
                "mutation_points": [0],
                "expected_feedback": ["protocol_error", "unexpected_state_advance"],
                "reason": "move the boundary command before its state-reaching prefix",
            }
        )
        variants.append(
            {
                "variant": "duplicate_boundary_message",
                "objective": "Exercise replay/idempotency behavior around the disputed transition.",
                "messages": messages[: last_index + 1] + [messages[last_index]] + messages[last_index + 1 :],
                "mutation_points": [last_index, last_index + 1],
                "expected_feedback": ["state_reuse", "unexpected_duplicate_acceptance"],
                "reason": "duplicate the boundary message selected by mutation_points",
            }
        )
        variants.append(
            {
                "variant": "recovery_after_error",
                "objective": "Check whether an invalid early command corrupts later valid state recovery.",
                "messages": [messages[-1], *messages],
                "mutation_points": [0, len(messages)],
                "expected_feedback": ["parser_recovery", "state_desynchronization"],
                "reason": "prepend the target command as an error before the valid prefix",
            }
        )
    return variants


def _direct_trigger_messages(path: PlannedStatePath, conflict: Conflict | None, messages: list[str]) -> list[str]:
    if not conflict or not conflict.transition:
        return []
    trigger = conflict.transition.split("->", 1)[0].strip()
    if "--" in trigger:
        trigger = trigger.split("--", 1)[1].strip()
    trigger = trigger.split()[0] if trigger.split() else ""
    if not trigger:
        return []
    source = conflict.state
    prefix: list[str] = []
    for state, message in zip(path.states, messages):
        if state == source:
            break
        prefix.append(message)
    return prefix + [trigger]


def _missing_guard_messages(messages: list[str], guards: str, protocol: str, last_index: int) -> list[str]:
    proto = protocol.lower()
    if proto == "rtsp":
        mutated = list(messages)
        mutated[last_index] = _append_directive(mutated[last_index], "omit-session")
        if "transport" in guards:
            mutated[last_index] = _append_directive(mutated[last_index], "no-transport")
        return mutated
    if proto == "ftp":
        if any(token in guards for token in ("auth", "login", "user", "password")):
            return [message for message in messages if _method(message) not in {"USER", "PASS"}]
        if any(token in guards for token in ("data", "passive", "active", "transfer", "port", "pasv")):
            return [message for message in messages if _method(message) not in {"PORT", "PASV", "EPRT", "EPSV"}]
    if proto == "smtp":
        return [message for message in messages if _method(message) not in {"EHLO", "MAIL", "RCPT"}]
    return []


def _stale_guard_messages(messages: list[str], guards: str, protocol: str, last_index: int) -> list[str]:
    proto = protocol.lower()
    mutated = list(messages)
    if proto == "rtsp" and any(token in guards for token in ("session", "auth", "transport", "valid")):
        mutated[last_index] = _append_directive(mutated[last_index], "stale-session")
        return mutated
    if proto == "ftp" and any(token in guards for token in ("auth", "login", "password", "valid")):
        mutated = [
            _append_directive(message, "bad-argument") if _method(message) in {"PASS", "USER"} else message
            for message in mutated
        ]
        return mutated
    return []


def _malformed_guard_messages(messages: list[str], guards: str, protocol: str, last_index: int) -> list[str]:
    proto = protocol.lower()
    mutated = list(messages)
    if proto == "rtsp" and any(token in guards for token in ("session", "transport", "valid", "auth")):
        mutated[last_index] = _append_directive(mutated[last_index], "malformed-guard")
        return mutated
    if proto in {"ftp", "smtp", "http", "daap-http"}:
        mutated[last_index] = _append_directive(mutated[last_index], "malformed")
        return mutated
    return []


def _priority(conflict: Conflict | None, path: PlannedStatePath, variant: str) -> int:
    score = {"P0": 220, "P1": 170, "P2": 120}.get(conflict.priority if conflict else "P2", 120)
    score += min(80, 20 * len(path.required_guards))
    score += min(60, 10 * len(path.messages))
    if variant in {"missing_guard_material", "stale_session_value", "malformed_guard_field"}:
        score += 80
    elif variant in {"direct_divergent_trigger", "wrong_message_order"}:
        score += 60
    elif variant in {"duplicate_boundary_message", "recovery_after_error"}:
        score += 35
    return min(500, max(50, score))


def _last_mutation_index(path: PlannedStatePath, messages: list[str]) -> int:
    if not messages:
        return 0
    valid = [item for item in path.mutation_points if 0 <= item < len(messages)]
    return valid[-1] if valid else len(messages) - 1


def _append_directive(message: str, directive: str) -> str:
    return message if f"--{directive}" in message else f"{message} --{directive}"


def _clean_messages(messages: list[str]) -> list[str]:
    return [str(message).strip() for message in messages if str(message).strip()]


def _method(message: str) -> str:
    return message.split()[0].upper() if message.split() else message.upper()


def _canonical_message(message: str) -> str:
    return " ".join(str(message).strip().split()).lower()
