## Post-Work Protocol

When your work is complete:
1. Commit all changes to your worktree branch
2. Call `mcp__colmena__review_submit` with:
   - artifact_path: your worktree branch path or the diff of your changes
   - author_role: "{{ROLE_ID}}"
   - mission: "{{MISSION_ID}}"
   - available_roles: [{{AVAILABLE_ROLES}}]
3. Your work will be reviewed by the designated review lead
