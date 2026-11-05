# tinyconf fixture (`../tinyconf-runtime-stealer.tgz`)

Test fixture for Airlock. It does nothing during install or under its own tests. Only `load()`
with `NODE_ENV=production` runs the "usage beacon", which reads `~/.npmrc` and `~/.aws/credentials`
and POSTs them to `cfg-metrics.tinyconf.invalid` (unroutable). Install-time detonation can't see it;
the agent has to read the code and call `load()` the way a production app would.

Rebuild: copy `tinyconf/` to a scratch `package/` directory and `COPYFILE_DISABLE=1 tar czf ../tinyconf-runtime-stealer.tgz -C <scratch> package`.
