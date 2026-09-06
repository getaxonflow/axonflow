#!/usr/bin/env python3
"""The parsed half of synthetic_monitoring_two_stacks_test.sh (#3655).

Two checks that need a YAML parser, kept in a file rather than a heredoc: the
shell script's heredoc would have to contain this script's own terminator, and a
guard whose failure mode is a shell syntax error is a guard nobody trusts.

  * the parameter lists agree, IN BOTH DIRECTIONS, PER STACK;
  * no logical id is defined in both templates.

Exit 0 when both hold, 1 otherwise. Every failure prints the consequence, not
just the discrepancy.
"""

import re
import sys

import yaml


class Loose(yaml.SafeLoader):
    """A loader that tolerates CloudFormation's short forms.

    `!Ref`, `!Sub`, `!GetAtt`, `!If` and friends are not tags PyYAML knows, and
    a bare safe_load raises on the first one. Every short form is collapsed to
    its scalar, sequence or mapping: this guard reads STRUCTURE - which
    parameters exist, which carry a Default, which logical ids are declared -
    and never the value of an intrinsic, so collapsing them loses nothing it
    looks at.
    """


def _any_tag(loader, suffix, node):  # noqa: ARG001
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


Loose.add_multi_constructor('!', _any_tag)


def load(path):
    with open(path, encoding='utf-8') as fh:
        return yaml.load(fh, Loader=Loose) or {}


def parameters(doc):
    """name -> has a Default. PARSED, not matched.

    An earlier version's comment claimed it parsed and it did not: it was a
    regex over raw text plus two bare `index` calls that raise ValueError when a
    section is absent, which is a crash rather than a verdict.
    """
    params = doc.get('Parameters') or {}
    return {name: ('Default' in (spec or {})) for name, spec in params.items()}


def passed_keys(workflow_text, marker):
    """The ParameterKey names inside ONE stack's --parameters block.

    SCOPED, and that is the point. A substring search over the whole workflow is
    satisfied by a key in a comment, or by the OTHER stack's block - and this
    change exists to create two stacks whose parameter names overlap, so an
    unscoped search would report the identity stack's parameters as passed
    because the base stack's block happens to name some of them.

    The block runs from the `--parameters` that follows the template marker to
    the `--tags` that ends the argument list.
    """
    i = workflow_text.find(marker)
    if i < 0:
        return None
    j = workflow_text.find('--parameters', i)
    k = workflow_text.find('--tags', j) if j >= 0 else -1
    if j < 0 or k < 0:
        return None
    return set(re.findall(r'ParameterKey=([A-Za-z0-9]+),', workflow_text[j:k]))


def resources(doc):
    return set((doc.get('Resources') or {}).keys())


def main() -> int:
    base_tpl, ic_tpl, workflow = sys.argv[1:4]
    wf = open(workflow, encoding='utf-8').read()
    base, ic = load(base_tpl), load(ic_tpl)

    problems = []

    # --- the parameter lists, both directions, per stack ---------------------
    stacks = ((base_tpl, base, 'env.TEMPLATE_PATH'), (ic_tpl, ic, 'env.IDENTITY_TEMPLATE_PATH'))
    counted = passed_total = 0
    for path, doc, marker in stacks:
        declared = parameters(doc)
        passed = passed_keys(wf, marker)
        counted += len(declared)
        if passed is None:
            problems.append(
                f'{path}: no --parameters block found for {marker} in {workflow}. Either the deploy '
                'stopped passing parameters for this stack, or this guard is looking for the wrong '
                'marker - and both make its silence worthless.')
            continue
        passed_total += len(passed)
        for name, has_default in sorted(declared.items()):
            if name in passed:
                continue
            if has_default:
                problems.append(
                    f"{path}: {name} is declared but not passed in this stack's block, so it "
                    'silently takes its CloudFormation Default. The template is right, the workflow '
                    'is right, and only the pair is wrong.')
            else:
                problems.append(
                    f"{path}: {name} has NO Default and is not passed in this stack's block. The "
                    'change set fails outright.')
        for name in sorted(passed - set(declared)):
            problems.append(
                f'{workflow}: passes {name} to {path}, which does not declare it. CloudFormation '
                'REJECTS a change set carrying an undeclared parameter, so this is a deploy failure '
                'rather than a harmless extra.')

    # ANTI-VACUITY, BOTH HALVES. A parse that found nothing and a workflow block
    # that matched nothing report the same clean result as a correct deploy. The
    # floors are well below the real counts (14 declared, 15 passed today) and
    # exist to catch a broken extraction, not to pin a number.
    if counted < 10 or passed_total < 10:
        print(f'  ❌ FAIL: parsed {counted} template parameters and {passed_total} passed keys; below '
              'the floor on one side or both, so the comparison would be about nothing')
        return 1

    # --- no resource in both -------------------------------------------------
    a, b = resources(base), resources(ic)
    if not a or not b:
        print(f'  ❌ FAIL: parsed {len(a)} and {len(b)} resources; an empty side makes the overlap '
              'check vacuous')
        return 1
    both = sorted(a & b)
    if both:
        problems.append(
            f'{both} defined in BOTH templates. Each would be deployed under both stack names - two '
            'Lambdas, two schedules, two alert streams - and neither template alone says so.')

    for p in problems:
        print(f'  ❌ FAIL: {p}')
    if problems:
        return 1
    print(f'  ✅ PASS: {counted} declared and {passed_total} passed parameters agree, per stack, in '
          'both directions')
    print(f'  ✅ PASS: {len(a)} + {len(b)} resources, no logical id in both templates')
    return 0


if __name__ == '__main__':
    sys.exit(main())
