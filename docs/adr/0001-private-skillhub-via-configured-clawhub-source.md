---
status: accepted
---

# Connect private SkillHub through a configured ClawHub-compatible source

Hermes connects to a private SkillHub registry through a profile-scoped,
ClawHub-compatible Skill Source. This reuses SkillHub's published compatibility
contract while keeping authentication, network policy, provenance, scanning,
and updates in the existing Skills Hub source layer. We do not add an
iflytek-specific core integration or require a separate well-known-protocol
translation service: the former couples Hermes to another product, while the
latter adds an operational component and discards SkillHub's namespace-aware
search and version resolution semantics.
