- [ ] In-memory store
    - This should be the default because it will make sidre much easier to use
      for testing. A persistent store should be tucked away behind a `persistent`
      feature flag for use in more long lived testing environments.