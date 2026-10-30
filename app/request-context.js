import { AsyncLocalStorage } from 'node:async_hooks';

const storage = new AsyncLocalStorage();

export function runWithRequestContext(context, fn) {
  return storage.run(Object.freeze({ ...context }), fn);
}

export function requestContext() {
  return storage.getStore() || null;
}
