"""Vectors dec/*: the decision act through `check-act` (VR-18, ACT-09, ACT-10, VR-01, VR-06, VR-07, VR-11).

One generic method for a local human decision. The consumer is in the signed body and the verifier
supplies the consumer it is, so `dec/other-consumer` is `consumer_mismatch` (step 12) and an edit of
the consumer after signing is `bad_signature`. The action is text under one grammar (section 2.2):
each way to leave it is its own row, and every one is `body_schema`, a field of the body (ACT-10).
Every row has exactly one defect; the rows that pass step 9 are positives, so both vitni builds
verify their signatures.
"""
from lib import base, forge, inputs
from lib import checkrows

DECISION = inputs.DECISION
OTHER = base.hashstr(b"another decision outputs")


def _body(**edit):
    body = {"action": base.DECISION_ACTION, "consumer": base.DECISION_CONSUMER,
            "subject": base.DECISION_SUBJECT}
    body.update(edit)
    return body


def _consumer(name):
    return lambda p: p["ext"]["dev.handsal/act"]["body"].__setitem__("consumer", name)


def generate(ctx):
    fx = ctx.fixtures

    def row(name, jws, reason, **kwargs):
        checkrows.row(ctx, name, jws, reason, method=DECISION, **kwargs)

    ok = fx.decision()

    # the consumer is the domain separation: the same words and bytes signed for another consumer
    row("dec/other-consumer", ok, "consumer_mismatch", signers=["alice"], consumer="archive")
    row("dec/replay-same-decision-other-consumer", fx.decision(consumer="archive"), "consumer_mismatch",
        signers=["alice"])
    swapped = forge.tamper(ok, _consumer("archive"))
    row("dec/consumer-swapped", swapped, "bad_signature", bad=(["alice"], "bad_signature"),
        consumer="archive")

    # the words the caller asked for: the right consumer and another action or subject (VR-18, VR-07)
    row("dec/other-action", ok, "outputs_mismatch", signers=["alice"], action="forget item")
    row("dec/other-subject", ok, "outputs_mismatch", signers=["alice"], subject="ruling-0002")

    # inputs_hash and outputs_hash (VR-06, VR-07)
    row("dec/inputs-mismatch", ok, "inputs_mismatch", signers=["alice"],
        decision_b64=fx.request_b64(b"another content"))
    row("dec/outputs-mismatch", fx.decision(outputs_hash=base.hashstr(
        forge.jcs.emit({"action": "forget item", "subject": base.DECISION_SUBJECT}))),
        "outputs_mismatch", signers=["alice"])

    # no decision is permanent (VR-11): signed two hours before the fixture time, valid for one
    row("dec/expired", fx.decision(ts=base.shift(base.NOW, -7200)), "expired", signers=["alice"])

    # the grammar of `action` (section 2.2): lowercase words, single spaces, 1 to 24 characters
    for name, action in (("dec/action-uppercase-body-schema", "Ratify ruling"),
                         ("dec/action-double-space-body-schema", "ratify  ruling"),
                         ("dec/action-leading-space-body-schema", " ratify ruling"),
                         ("dec/action-trailing-space-body-schema", "ratify ruling "),
                         ("dec/action-digit-body-schema", "ratify ruling 2"),
                         ("dec/action-25-bytes-body-schema", base.DECISION_ACTION_24 + "x"),
                         ("dec/action-empty-body-schema", "")):
        row(name, fx.decision(action=action), "body_schema")
    # the forms of the other two body fields and the closed key set
    row("dec/subject-uppercase-body-schema", fx.decision(subject="Ruling-0001"), "body_schema")
    row("dec/consumer-uppercase-body-schema", fx.decision(consumer="Notes"), "body_schema")
    row("dec/body-extra-key-body-schema", fx.decision(body=_body(note="x")), "body_schema")
    # a decision has no recipient and no relay: the act object is closed (ACT-09)
    row("dec/recipient-key-schema", fx.decision(extra={"recipient": "alice"}), "schema")

    # required inputs (VR-01): the consumer and the content, and the consumer is a `consumer_id`
    row("dec/consumer-input-missing", ok, None, error="malformed_input", consumer=inputs.DROP)
    row("dec/consumer-input-form-malformed", ok, None, error="malformed_input", consumer="Notes")
    row("dec/decision-input-missing", ok, None, error="malformed_input", decision_b64=inputs.DROP)
    row("dec/action-input-missing", ok, None, error="malformed_input", action=inputs.DROP)
    row("dec/subject-input-missing", ok, None, error="malformed_input", subject=inputs.DROP)
    row("dec/action-input-form-malformed", ok, None, error="malformed_input", action="Ratify ruling")
    row("dec/subject-input-form-malformed", ok, None, error="malformed_input", subject="Ruling")
