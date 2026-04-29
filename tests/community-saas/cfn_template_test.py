#!/usr/bin/env python3
"""Regression tests for the community-saas CloudFormation template.

The community-saas stack runs at try.getaxonflow.com — the public
evaluation surface for AxonFlow. Two regressions surfaced in this
codebase had no in-repo guard:

  1. axonflow-enterprise#1747: SQLi system policies fired in `policies_evaluated`
     but never blocked, because the agent task in the community-saas CFN
     template didn't set SQLI_ACTION=block — it inherited the v6.2.0+
     relaxed default profile (`SQLI_ACTION=warn`).

  2. axonflow-enterprise#1751: long MAP plan-generation requests 504'd
     at the ALB. The CFN template's `AlbIdleTimeoutSeconds` parameter
     existed with `Default: 300`, but if a future cleanup lowers it
     below the orchestrator's plan-cap, plans 504 again.

These tests pin the structural guarantees so a future template edit
that removes the SQLi enforcement env, drops the ALB-timeout default,
or weakens the parameter constraints fails the gate before merge.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATE = REPO_ROOT / "infrastructure" / "cloudformation" / "community-saas-ecs.yaml"


class _CFNLoader(yaml.SafeLoader):
    """YAML loader that tolerates CloudFormation short-form intrinsics
    (`!Ref`, `!Sub`, `!GetAtt`, etc.). The values get loaded as a
    plain string holding the argument so structural assertions still
    work without needing cfn-flip."""


def _cfn_short_form(loader: yaml.Loader, tag: str, node: yaml.Node):  # noqa: ANN401
    if isinstance(node, yaml.ScalarNode):
        return {tag: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag: loader.construct_sequence(node)}
    if isinstance(node, yaml.MappingNode):
        return {tag: loader.construct_mapping(node)}
    return None


for _tag in [
    "!Ref",
    "!Sub",
    "!GetAtt",
    "!Join",
    "!If",
    "!Select",
    "!Split",
    "!FindInMap",
    "!ImportValue",
    "!Equals",
    "!And",
    "!Or",
    "!Not",
    "!Cidr",
    "!Base64",
    "!Condition",
    "!Transform",
    "!Length",
    "!ToJsonString",
]:
    _CFNLoader.add_constructor(
        _tag,
        # capture _tag in default arg so the closure isn't stale.
        lambda loader, node, tag=_tag: _cfn_short_form(loader, tag, node),
    )


@pytest.fixture(scope="module")
def template():
    if not TEMPLATE.is_file():
        pytest.skip(f"template not found at {TEMPLATE}")
    with TEMPLATE.open() as f:
        return yaml.load(f, Loader=_CFNLoader)


@pytest.fixture(scope="module")
def parameters(template):
    return template.get("Parameters") or {}


@pytest.fixture(scope="module")
def agent_task(template):
    resources = template.get("Resources") or {}
    task = resources.get("AgentTaskDefinition")
    assert task is not None, "AgentTaskDefinition missing from template"
    return task


@pytest.fixture(scope="module")
def agent_environment(agent_task):
    """Return the agent container's Environment as a name -> value-spec
    dict. value-spec preserves the CFN intrinsic shape (`{!Ref: ...}`)
    so callers can assert against `!Ref`-driven values."""
    container_defs = (agent_task.get("Properties") or {}).get("ContainerDefinitions") or []
    assert container_defs, "AgentTaskDefinition has no container definitions"
    env_list = container_defs[0].get("Environment") or []
    return {entry["Name"]: entry.get("Value") for entry in env_list if "Name" in entry}


# axonflow-enterprise#1747 ---------------------------------------------


def test_sqli_action_parameter_exists(parameters):
    """SqliAction CFN parameter must exist with the expected shape."""
    assert "SqliAction" in parameters, (
        "SqliAction parameter missing from community-saas template — see #1747. "
        "The community SaaS is the public evaluation surface and must demonstrate "
        "SQLi blocking out of the box, not the platform-wide v6.2.0+ relaxed default."
    )
    spec = parameters["SqliAction"]
    assert spec.get("Type") == "String", (
        f"SqliAction Type expected 'String', got {spec.get('Type')!r}"
    )
    assert spec.get("Default") == "block", (
        f"SqliAction Default expected 'block' (the headline governance demo), "
        f"got {spec.get('Default')!r}. Lowering the default to 'warn' would silently "
        "make try.getaxonflow.com stop blocking SQLi again."
    )
    allowed = spec.get("AllowedValues") or []
    assert sorted(allowed) == ["block", "log", "warn"], (
        f"SqliAction AllowedValues expected ['block', 'log', 'warn'], got {allowed!r}"
    )


def test_agent_environment_wires_sqli_action(agent_environment):
    """The agent container must surface SQLI_ACTION env from the param."""
    assert "SQLI_ACTION" in agent_environment, (
        "SQLI_ACTION missing from AgentTaskDefinition.ContainerDefinitions[0].Environment "
        "— see #1747. Without this env var the agent inherits the platform-wide default "
        "profile (warn) and SQLi never blocks on community-saas."
    )
    value = agent_environment["SQLI_ACTION"]
    assert value == {"!Ref": "SqliAction"}, (
        "SQLI_ACTION env should be wired via !Ref SqliAction so the parameter's "
        "AllowedValues constraint applies; got "
        f"{value!r}."
    )


# axonflow-enterprise#1751 ---------------------------------------------


def test_alb_idle_timeout_parameter_default(parameters):
    """AlbIdleTimeoutSeconds must default to >=300s.

    The orchestrator's MAP plan cap is 300s by default; an ALB idle
    timeout below that lets long plan-generation requests 504 at the
    front door. We pin the lower bound at 300 so a cleanup that lowers
    the default reintroduces the gap surfaced by #1751.
    """
    assert "AlbIdleTimeoutSeconds" in parameters, (
        "AlbIdleTimeoutSeconds parameter missing from community-saas template — see #1751."
    )
    spec = parameters["AlbIdleTimeoutSeconds"]
    default = spec.get("Default")
    assert default is not None, "AlbIdleTimeoutSeconds must declare Default"
    # CFN parameter Default values for Type: Number can be int OR float;
    # Default is the only constraint we assert here. MinValue/MaxValue
    # are checked separately because they bound future overrides.
    assert int(default) >= 300, (
        f"AlbIdleTimeoutSeconds Default {default!r} is below 300s. "
        "Lowering the default below the orchestrator's plan cap reintroduces "
        "the 504 gateway timeout surfaced by #1751."
    )


def test_alb_idle_timeout_parameter_min_value(parameters):
    """Lower bound must be >=60 so a legacy value can't be re-pinned at AWS default."""
    spec = parameters.get("AlbIdleTimeoutSeconds") or {}
    min_value = spec.get("MinValue")
    assert min_value is not None and int(min_value) >= 60, (
        f"AlbIdleTimeoutSeconds MinValue must be >= 60, got {min_value!r}"
    )


# Smoke test the suite is wired ----------------------------------------


def test_template_has_expected_resources(template):
    """Sanity check: the template still has the AgentTaskDefinition + ALB
    resources the other tests assume. Catches a structural rename."""
    resources = template.get("Resources") or {}
    for key in ["AgentTaskDefinition", "OrchestratorTaskDefinition"]:
        assert key in resources, f"Resource {key!r} missing — fixture references will go stale"


###############################################################################
# Synthetic-failure proofs                                                    #
###############################################################################
#
# Without these, a future refactor that softens the assertions (e.g. drops
# `assert default == 'block'` in favour of `assert 'Default' in spec`) makes
# the gate a no-op without anyone noticing. These tests deliberately
# construct broken templates and assert the assertion functions reject
# them, so a softened check fails BOTH the live template assertion AND its
# synthetic-failure proof.


def _run_assertion(fn, fixture_template):
    """Helper: call one of the assertion functions above with a synthetic
    in-memory template and return (raised, message)."""
    parameters = fixture_template.get("Parameters") or {}
    container_defs = (
        (fixture_template.get("Resources") or {})
        .get("AgentTaskDefinition", {})
        .get("Properties", {})
        .get("ContainerDefinitions", [])
    )
    env = (
        {entry["Name"]: entry.get("Value") for entry in container_defs[0].get("Environment", [])}
        if container_defs
        else {}
    )
    try:
        if fn == "sqli_param":
            test_sqli_action_parameter_exists(parameters)
        elif fn == "sqli_env":
            test_agent_environment_wires_sqli_action(env)
        elif fn == "alb_default":
            test_alb_idle_timeout_parameter_default(parameters)
        elif fn == "alb_min":
            test_alb_idle_timeout_parameter_min_value(parameters)
        elif fn == "resources":
            test_template_has_expected_resources(fixture_template)
    except AssertionError as e:
        return True, str(e)
    return False, ""


def _good_template():
    return {
        "Parameters": {
            "SqliAction": {
                "Type": "String",
                "Default": "block",
                "AllowedValues": ["block", "warn", "log"],
            },
            "AlbIdleTimeoutSeconds": {
                "Type": "Number",
                "Default": 300,
                "MinValue": 60,
                "MaxValue": 1800,
            },
        },
        "Resources": {
            "AgentTaskDefinition": {
                "Properties": {
                    "ContainerDefinitions": [
                        {
                            "Environment": [
                                {"Name": "SQLI_ACTION", "Value": {"!Ref": "SqliAction"}},
                            ],
                        },
                    ],
                },
            },
            "OrchestratorTaskDefinition": {},
        },
    }


def test_synthetic_failure_sqli_param_missing():
    bad = _good_template()
    del bad["Parameters"]["SqliAction"]
    raised, _ = _run_assertion("sqli_param", bad)
    assert raised, "synthetic-failure check did not fire — gate would silently pass"


def test_synthetic_failure_sqli_default_warn():
    bad = _good_template()
    bad["Parameters"]["SqliAction"]["Default"] = "warn"
    raised, msg = _run_assertion("sqli_param", bad)
    assert raised, "synthetic-failure check did not fire on Default=warn"
    assert "block" in msg.lower(), msg


def test_synthetic_failure_sqli_env_not_wired():
    bad = _good_template()
    bad["Resources"]["AgentTaskDefinition"]["Properties"]["ContainerDefinitions"][0][
        "Environment"
    ] = []
    raised, _ = _run_assertion("sqli_env", bad)
    assert raised, "synthetic-failure check did not fire when SQLI_ACTION env was removed"


def test_synthetic_failure_sqli_env_hardcoded():
    bad = _good_template()
    # Hardcoded value bypasses the AllowedValues constraint on the parameter.
    bad["Resources"]["AgentTaskDefinition"]["Properties"]["ContainerDefinitions"][0][
        "Environment"
    ] = [{"Name": "SQLI_ACTION", "Value": "block"}]
    raised, _ = _run_assertion("sqli_env", bad)
    assert raised, "synthetic-failure check did not fire when SQLI_ACTION was hardcoded"


def test_synthetic_failure_alb_default_below_300():
    bad = _good_template()
    bad["Parameters"]["AlbIdleTimeoutSeconds"]["Default"] = 60
    raised, msg = _run_assertion("alb_default", bad)
    assert raised, "synthetic-failure check did not fire when ALB Default dropped below 300"
    assert "300" in msg, msg


def test_synthetic_failure_alb_min_below_60():
    bad = _good_template()
    bad["Parameters"]["AlbIdleTimeoutSeconds"]["MinValue"] = 30
    raised, _ = _run_assertion("alb_min", bad)
    assert raised, "synthetic-failure check did not fire when ALB MinValue dropped below 60"


def test_synthetic_failure_resources_renamed():
    bad = _good_template()
    bad["Resources"]["AgentTaskDef"] = bad["Resources"].pop("AgentTaskDefinition")
    raised, _ = _run_assertion("resources", bad)
    assert raised, "synthetic-failure check did not fire when AgentTaskDefinition was renamed"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
