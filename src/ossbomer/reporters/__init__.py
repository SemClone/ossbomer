"""ossbomer.reporters — output renderers.

Requirement R10: unified output in three modes — human-readable console,
machine-readable JSON, and SARIF for CI ingestion. SARIF emits one `run` per
profile, so CI systems surface each profile as its own scan rather than blending
them. HTML output is still optional and not implemented.

See :mod:`ossbomer.reporters.render`.
"""
