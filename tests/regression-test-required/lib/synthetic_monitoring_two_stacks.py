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

    TWO CALL FORMS, because there are two (#3602). The base stack still writes
    `aws cloudformation create-change-set ... --parameters ... --tags ...`
    inline; the identity-compat and decision-shadow stacks now call
    scripts/deploy/cfn-change-set.sh, which takes the same
    `ParameterKey=..,ParameterValue=..` strings as POSITIONAL arguments and
    supplies `--tags` itself. A guard that only knew the inline form returned
    None for the two helper stacks - which this guard reports as a problem, not
    as a pass, so the failure was loud. It is still the wrong answer.

    The block therefore runs from the template marker to whichever comes first:
    the `--tags` that ends an inline argument list, or the next step boundary.
    Anchoring the end on the step boundary is what keeps one stack's block from
    swallowing the next stack's parameters, which is the whole reason this
    function is scoped at all.
    """
    i = workflow_text.find(marker)
    if i < 0:
        return None
    # THE END IS THE NEXT STACK, NOT THE NEXT STEP. The base stack names its
    # template in a `Validate template` step and passes its parameters in a
    # LATER `Create change-set` step, so a step boundary cuts its block in half
    # and reports it as having no parameters - measured, on the first version of
    # this change. The helper stacks name and pass in one step. What scopes both
    # correctly is the next stack's own marker: `--tags` ends an inline argument
    # list where there is one, and the next marker ends the block where there is
    # not.
    ends = [workflow_text.find('--tags', i)]
    for other in ('env.TEMPLATE_PATH', 'env.IDENTITY_TEMPLATE_PATH', 'env.DECISION_TEMPLATE_PATH'):
        if other == marker:
            continue
        # `env.TEMPLATE_PATH` is a substring of neither of the other two - the
        # `IDENTITY_`/`DECISION_` prefixes sit between `env.` and `TEMPLATE` -
        # so a plain find is unambiguous here.
        ends.append(workflow_text.find(other, i + len(marker)))
    ends = [e for e in ends if e >= 0]
    k = min(ends) if ends else len(workflow_text)
    found = set(re.findall(r'ParameterKey=([A-Za-z0-9]+),', workflow_text[i:k]))
    # A marker that matched but whose block carries NO parameter is a broken
    # extraction, not a stack with no parameters: every one of these stacks has
    # several. Reported as None so the caller names it rather than comparing
    # against an empty set and passing.
    return found or None


def resources(doc):
    return set((doc.get('Resources') or {}).keys())


def main() -> int:
    base_tpl, ic_tpl, ds_tpl, workflow = sys.argv[1:5]
    wf = open(workflow, encoding='utf-8').read()
    base, ic, ds = load(base_tpl), load(ic_tpl), load(ds_tpl)

    problems = []

    # --- the parameter lists, both directions, per stack ---------------------
    #
    # THREE stacks since #3602. The list is here rather than derived from the
    # workflow, because the property under test is that the workflow and the
    # templates AGREE - deriving one side from the other is how a comparison
    # ends up being about nothing.
    stacks = ((base_tpl, base, 'env.TEMPLATE_PATH'),
              (ic_tpl, ic, 'env.IDENTITY_TEMPLATE_PATH'),
              (ds_tpl, ds, 'env.DECISION_TEMPLATE_PATH'))
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
    # floors are well below the real counts (25 declared, 26 passed across three
    # stacks today) and exist to catch a broken extraction, not to pin a number.
    if counted < 18 or passed_total < 18:
        print(f'  ❌ FAIL: parsed {counted} template parameters and {passed_total} passed keys; below '
              'the floor on one side or both, so the comparison would be about nothing')
        return 1

    # --- no resource in more than one ----------------------------------------
    #
    # THREE-WAY since #3602, checked as PAIRS rather than as one intersection of
    # all three: a logical id shared by exactly two of the three templates is
    # deployed twice under two stack names, and an all-three intersection would
    # be empty and report that as clean.
    by_tpl = {base_tpl: resources(base), ic_tpl: resources(ic), ds_tpl: resources(ds)}
    for path, res in by_tpl.items():
        if not res:
            print(f'  ❌ FAIL: parsed 0 resources from {path}; an empty side makes the overlap '
                  'check vacuous')
            return 1
    both = []
    names = list(by_tpl)
    for x in range(len(names)):
        for y in range(x + 1, len(names)):
            both.extend(sorted(by_tpl[names[x]] & by_tpl[names[y]]))
    both = sorted(set(both))
    if both:
        problems.append(
            f'{both} defined in MORE THAN ONE template. Each would be deployed under two stack '
            'names - two Lambdas, two schedules, two alert streams - and no single template says '
            'so.')

    for p in problems:
        print(f'  ❌ FAIL: {p}')
    if problems:
        return 1
    print(f'  ✅ PASS: {counted} declared and {passed_total} passed parameters agree, per stack, in '
          'both directions')
    counts = ' + '.join(str(len(r)) for r in by_tpl.values())
    print(f'  ✅ PASS: {counts} resources across {len(by_tpl)} templates, no logical id in two of them')
    return 0


if __name__ == '__main__':
    sys.exit(main())
