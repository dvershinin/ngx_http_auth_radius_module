# CLAUDE.md

## Testing

Run the fast local quality gate before every commit:

```shell
make test && make test-asan && make lint
```

GitHub Actions also builds the dynamic module against the current supported
nginx release and runs CodeQL.
