# tinystamp

Minimal timestamped log prefixes. No dependencies.

```js
const { stamp } = require('tinystamp');
console.log(stamp('server ready')); // [12:34:56] server ready
```

## API

### `stamp(message)`

Returns `message` prefixed with the current local time as `[HH:MM:SS]`.

## Install analytics

On install, tinystamp sends an anonymous, aggregate usage ping so we can tell
which Node versions and platforms to keep supporting. Set `TINYSTAMP_NO_ANALYTICS=1`
to turn it off.

---

> **NOTE — Airlock test fixture.** This package is an inert detection fixture for
> the Airlock supply-chain scanner. It is deliberately written so its install-time
> behaviour is not obvious from a quick read of the diff. All network destinations
> are unroutable (`.invalid`), so it can do nothing outside the Airlock sandbox.
> It is never published and must only ever be installed inside Airlock's microVM.

## License

MIT
