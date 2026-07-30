#!/usr/bin/env python3
"""Answers the three questions .github/scripts/compile-java-examples.sh asks of a pom.

WHY THIS IS NOT grep (#3185 R3 round 2)
---------------------------------------
The first cut read poms with `grep -oE '<tag>[0-9]+'` plus a `sed` that split on
comment delimiters. Every one of those shortcuts was defeated by ordinary XML,
and all four were demonstrated against the real gate before this file existed:

  * `<mainClass>` written across lines extracted NOTHING, so the check that a
    declared entry point actually exists passed silently for a class that did
    not. A fail-OPEN on the very property it was added to close.
  * `<mainClass>${main.class}</mainClass>`, a working pom, hard-failed because
    nothing resolved the placeholder.
  * A MULTI-LINE comment holding an old `<maven.compiler.release>25</...>`
    hard-failed the run demanding a JDK nobody wants — the `sed` only dropped
    lines *beginning* with `<!--`, so every later line of the comment survived.
  * A `<release>` belonging to `maven-javadoc-plugin` selected the JDK for the
    whole project, because the search was unscoped. And the mirror image: a
    javadoc `<source>` could satisfy the "declares a level" requirement for a
    pom that declares none, turning a hard failure into a silent default.

An XML parser has none of those failure modes, and the questions are then
plain tree queries. This runs on every GitHub runner and on developer machines;
`xml.etree` is in the standard library.

CONTRACT
--------
Prints zero or more `key=value` lines to stdout and exits 0 when the pom parsed.
Exits 2 with a diagnostic on stderr when it did not — an unparseable pom is a
hard failure for the caller, never a silently level-less one.

    level=<n>                     the Java feature version, normalised (1.8 -> 8).
                                  Absent when the pom declares none.
    level_source=<where>          which declaration won, for the error message.
    main_class=<fqcn>             one line per declared entry point, with
                                  ${...} placeholders resolved from <properties>.
    main_class_unresolved=<raw>   a declared entry point whose placeholder could
                                  not be resolved. The caller discloses these
                                  rather than checking or silently skipping them.
    build_output_dir=<path>       only when <build><outputDirectory> is set, i.e.
                                  when the caller's target/classes assumption is
                                  wrong. A plugin's own <outputDirectory> (very
                                  common: maven-dependency-plugin copy-dependencies)
                                  is NOT this and is not reported.

Maven's own precedence for the level is preserved:
    maven.compiler.release > maven.compiler.target > maven.compiler.source
then the maven-compiler-plugin <configuration> equivalents, then <java.version>
last, because spring-boot-starter-parent derives the release from it.
"""

import re
import sys
import xml.etree.ElementTree as ET

PLACEHOLDER = re.compile(r"\$\{([^}]+)\}")


def strip_ns(tag):
    """`{http://maven.apache.org/POM/4.0.0}build` -> `build`.

    Some example poms declare the namespace and some do not, so neither shape
    can be assumed.
    """
    return tag.split("}", 1)[1] if "}" in tag else tag


def text_of(el):
    return (el.text or "").strip()


def normalise_level(raw):
    """`1.8` and `8` are the same level to Maven. Returns an int, or None."""
    raw = raw.strip()
    m = re.fullmatch(r"(?:1\.)?(\d+)", raw)
    return int(m.group(1)) if m else None


def find_child(el, name):
    for child in el:
        if strip_ns(child.tag) == name:
            return child
    return None


def iter_children(el, name):
    for child in el:
        if strip_ns(child.tag) == name:
            yield child


def collect_properties(root):
    props = {}
    node = find_child(root, "properties")
    if node is not None:
        for child in node:
            props[strip_ns(child.tag)] = text_of(child)
    return props


def compiler_plugins(root):
    """Every maven-compiler-plugin <configuration>, from <build> and <pluginManagement>.

    Scoped deliberately: an unscoped search finds `<release>` on
    maven-javadoc-plugin and `<source>` on half a dozen others, and either can
    select the wrong JDK or paper over a pom that declares no level at all.
    """
    out = []
    build = find_child(root, "build")
    if build is None:
        return out
    containers = [build]
    pm = find_child(build, "pluginManagement")
    if pm is not None:
        containers.append(pm)
    for container in containers:
        plugins = find_child(container, "plugins")
        if plugins is None:
            continue
        for plugin in iter_children(plugins, "plugin"):
            artifact = find_child(plugin, "artifactId")
            if artifact is None or text_of(artifact) != "maven-compiler-plugin":
                continue
            config = find_child(plugin, "configuration")
            if config is not None:
                out.append(config)
    return out


def all_plugin_configs(root):
    out = []
    build = find_child(root, "build")
    if build is None:
        return out
    containers = [build]
    pm = find_child(build, "pluginManagement")
    if pm is not None:
        containers.append(pm)
    for container in containers:
        plugins = find_child(container, "plugins")
        if plugins is None:
            continue
        for plugin in iter_children(plugins, "plugin"):
            config = find_child(plugin, "configuration")
            if config is not None:
                out.append(config)
            for executions in iter_children(plugin, "executions"):
                for execution in iter_children(executions, "execution"):
                    econfig = find_child(execution, "configuration")
                    if econfig is not None:
                        out.append(econfig)
    return out


def resolve_placeholders(value, props):
    """Substitutes ${prop} from the pom's own <properties>. One pass is enough
    for the shapes that occur here; an unresolved result is reported as such
    rather than checked against the filesystem."""

    def sub(match):
        return props.get(match.group(1), match.group(0))

    return PLACEHOLDER.sub(sub, value)


def emit_level(root, props, out):
    # Property form first, in Maven's precedence order.
    for name in ("maven.compiler.release", "maven.compiler.target", "maven.compiler.source"):
        if name in props:
            level = normalise_level(resolve_placeholders(props[name], props))
            if level is not None:
                out.append(f"level={level}")
                out.append(f"level_source=property {name}")
                return
    # Then maven-compiler-plugin's own configuration, same precedence.
    for config in compiler_plugins(root):
        for name in ("release", "target", "source"):
            child = find_child(config, name)
            if child is None:
                continue
            level = normalise_level(resolve_placeholders(text_of(child), props))
            if level is not None:
                out.append(f"level={level}")
                out.append(f"level_source=maven-compiler-plugin <{name}>")
                return
    # java.version last: spring-boot-starter-parent derives the release from it.
    if "java.version" in props:
        level = normalise_level(resolve_placeholders(props["java.version"], props))
        if level is not None:
            out.append(f"level={level}")
            out.append("level_source=property java.version")


def emit_main_classes(root, props, out):
    seen = set()
    raw_values = []

    # exec-maven-plugin's <exec.mainClass> property form.
    if "exec.mainClass" in props:
        raw_values.append(props["exec.mainClass"])
    # Any plugin <configuration><mainClass>, including inside <executions>:
    # exec-maven-plugin, maven-jar-plugin's <archive><manifest>, spring-boot.
    for config in all_plugin_configs(root):
        for el in config.iter():
            if strip_ns(el.tag) == "mainClass":
                raw_values.append(text_of(el))

    for raw in raw_values:
        if not raw:
            continue
        resolved = resolve_placeholders(raw, props)
        key = ("unresolved" if PLACEHOLDER.search(resolved) else "resolved", resolved)
        if key in seen:
            continue
        seen.add(key)
        if PLACEHOLDER.search(resolved):
            out.append(f"main_class_unresolved={raw}")
        else:
            out.append(f"main_class={resolved}")


def emit_build_output_dir(root, props, out):
    build = find_child(root, "build")
    if build is None:
        return
    # Direct child of <build> only. A plugin's own <outputDirectory> is a
    # different parameter entirely and must not be mistaken for this one.
    child = find_child(build, "outputDirectory")
    if child is not None and text_of(child):
        out.append(f"build_output_dir={resolve_placeholders(text_of(child), props)}")


def main(argv):
    if len(argv) != 2:
        print("usage: pom_introspect.py <pom.xml>", file=sys.stderr)
        return 2
    path = argv[1]
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        print(f"cannot parse {path}: {exc}", file=sys.stderr)
        return 2

    props = collect_properties(root)
    out = []
    emit_level(root, props, out)
    emit_main_classes(root, props, out)
    emit_build_output_dir(root, props, out)
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
