# Pull Request

## Summary

<!-- What does this PR do? One paragraph. -->

## Type of Change

- [ ] Bug fix
- [ ] New scanner integration
- [ ] New language client
- [ ] Documentation
- [ ] CI/CD improvement
- [ ] Refactor / code quality
- [ ] Other: ___

## Checklist

### For all PRs
- [ ] I am assigned to the issue this PR fixes (linked below)
- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] My code follows the project style (ruff / gofmt / eslint clean)
- [ ] I have added or updated tests for my changes
- [ ] All existing tests pass (`pytest` / `go test ./...` / `npm test`)
- [ ] I have updated relevant documentation

### For new scanner integrations
- [ ] Tool is open source or has a free tier
- [ ] Tool runner function is in the correct `tools/<category>.py` file
- [ ] Tool is registered in `server.py` (`list_tools` + `call_tool` + `TOOLS_REGISTRY`)
- [ ] Tests cover: tool-not-installed, JSON parsing, error handling
- [ ] Added to `docs/tool-setup.md` with install instructions
- [ ] Added to `README.md` tools table

### For new language clients
- [ ] Client follows the server resolution order (env var → CLI → uvx → python -m)
- [ ] Client has its own README with usage examples
- [ ] Build/test CI added in `.github/workflows/`

## Testing Done

<!-- How did you test this? Include sample output if relevant. -->

```
paste output here
```

## Related Issue

<!-- Required for contributors: the issue assigned to you. The "Issue assignment"
     check blocks the merge until this PR references an issue assigned to its author.
     Not assigned yet? Comment on the issue with a short plan and wait for a maintainer. -->

Fixes #___
