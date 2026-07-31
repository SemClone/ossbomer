"""ossbomer.scoring — quality scoring (R9).

Requirement R9: in addition to a pass/fail verdict, each profile emits a quality
score. When multiple profiles are supplied in one invocation, the tool emits an
independent verdict + score per profile; scores are NEVER blended or averaged
across profiles.

Five orthogonal categories (Completeness, Accuracy, Consistency, Provenance,
Freshness) each score 0-100, and a weighted composite combines them. The weights
come from the profile, so a strict profile can lean on Provenance and Accuracy
while a permissive one leans on Completeness. See :mod:`ossbomer.scoring.scorer`.
"""
