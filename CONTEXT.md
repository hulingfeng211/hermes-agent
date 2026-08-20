# Skills Distribution

This context defines how Hermes discovers and acquires versioned skills from
organization-managed and public registries.

## Language

**Private SkillHub**:
An organization-operated SkillHub registry whose visible skills are determined by the caller's identity and namespace permissions.
_Avoid_: Enterprise Skill Source, private skills directory

**Skill Source**:
A profile-scoped registry connection through which Hermes discovers and retrieves skill bundles.
_Avoid_: Hub, endpoint, marketplace

**Skill Coordinate**:
The stable identity of a skill, consisting of its namespace and slug.
_Avoid_: Skill name, path

**Compatibility Slug**:
The flattened representation of a Skill Coordinate used by ClawHub-compatible clients, such as `team--deploy-helper`.
_Avoid_: Skill ID, local directory name

**Published Skill Version**:
An immutable, installable release of a skill selected by a SkillHub registry.
_Avoid_: Latest copy, draft
