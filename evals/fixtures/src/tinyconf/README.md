# tinyconf

Layered configuration: defaults, then `config.json`, then `APP_*` environment variables.

```js
const conf = require('tinyconf').load({ defaults: { port: 3000 } });
```
