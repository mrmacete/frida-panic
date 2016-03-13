# frida-panic

Easy crash-reporting for [Frida](http://frida.re)-based applications.

## Example

In your agent.js:

```js
const panic = require('@viaforensics/frida-panic');

panic.handler.install({
  onPanic(error) {
    send({ name: '+panic', payload: error });
    recv('+panic-ack', _ => true).wait();
  }
});
```

In your application:

```js
const panic = require('@viaforensics/frida-panic');

...
script.events.listen('message', onMessage);

function onMessage(message, data) {
  if (message.type === 'send') {
    const stanza = message.payload;
    switch (stanza.name) {
    case '+panic':
      console.error(panic.format(stanza.payload));
      device.kill(pid);
      break;
    }
  }
}
```
