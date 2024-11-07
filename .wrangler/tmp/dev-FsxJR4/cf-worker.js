(() => {
  var __defProp = Object.defineProperty;
  var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

  // .wrangler/tmp/bundle-KY8Inb/checked-fetch.js
  var urls = /* @__PURE__ */ new Set();
  function checkURL(request, init) {
    const url = request instanceof URL ? request : new URL(
      (typeof request === "string" ? new Request(request, init) : request).url
    );
    if (url.port && url.port !== "443" && url.protocol === "https:") {
      if (!urls.has(url.toString())) {
        urls.add(url.toString());
        console.warn(
          `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
        );
      }
    }
  }
  __name(checkURL, "checkURL");
  globalThis.fetch = new Proxy(globalThis.fetch, {
    apply(target, thisArg, argArray) {
      const [request, init] = argArray;
      checkURL(request, init);
      return Reflect.apply(target, thisArg, argArray);
    }
  });

  // ../../node_modules/wrangler/templates/middleware/common.ts
  var __facade_middleware__ = [];
  function __facade_register__(...args) {
    __facade_middleware__.push(...args.flat());
  }
  __name(__facade_register__, "__facade_register__");
  function __facade_registerInternal__(...args) {
    __facade_middleware__.unshift(...args.flat());
  }
  __name(__facade_registerInternal__, "__facade_registerInternal__");
  function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
    const [head, ...tail] = middlewareChain;
    const middlewareCtx = {
      dispatch,
      next(newRequest, newEnv) {
        return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
      }
    };
    return head(request, env, ctx, middlewareCtx);
  }
  __name(__facade_invokeChain__, "__facade_invokeChain__");
  function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
    return __facade_invokeChain__(request, env, ctx, dispatch, [
      ...__facade_middleware__,
      finalMiddleware
    ]);
  }
  __name(__facade_invoke__, "__facade_invoke__");

  // ../../node_modules/wrangler/templates/middleware/loader-sw.ts
  var __FACADE_EVENT_TARGET__;
  if (globalThis.MINIFLARE) {
    __FACADE_EVENT_TARGET__ = new (Object.getPrototypeOf(WorkerGlobalScope))();
  } else {
    __FACADE_EVENT_TARGET__ = new EventTarget();
  }
  function __facade_isSpecialEvent__(type) {
    return type === "fetch" || type === "scheduled";
  }
  __name(__facade_isSpecialEvent__, "__facade_isSpecialEvent__");
  var __facade__originalAddEventListener__ = globalThis.addEventListener;
  var __facade__originalRemoveEventListener__ = globalThis.removeEventListener;
  var __facade__originalDispatchEvent__ = globalThis.dispatchEvent;
  globalThis.addEventListener = function(type, listener, options) {
    if (__facade_isSpecialEvent__(type)) {
      __FACADE_EVENT_TARGET__.addEventListener(
        type,
        listener,
        options
      );
    } else {
      __facade__originalAddEventListener__(type, listener, options);
    }
  };
  globalThis.removeEventListener = function(type, listener, options) {
    if (__facade_isSpecialEvent__(type)) {
      __FACADE_EVENT_TARGET__.removeEventListener(
        type,
        listener,
        options
      );
    } else {
      __facade__originalRemoveEventListener__(type, listener, options);
    }
  };
  globalThis.dispatchEvent = function(event) {
    if (__facade_isSpecialEvent__(event.type)) {
      return __FACADE_EVENT_TARGET__.dispatchEvent(event);
    } else {
      return __facade__originalDispatchEvent__(event);
    }
  };
  globalThis.addMiddleware = __facade_register__;
  globalThis.addMiddlewareInternal = __facade_registerInternal__;
  var __facade_waitUntil__ = Symbol("__facade_waitUntil__");
  var __facade_response__ = Symbol("__facade_response__");
  var __facade_dispatched__ = Symbol("__facade_dispatched__");
  var __Facade_ExtendableEvent__ = class extends Event {
    [__facade_waitUntil__] = [];
    waitUntil(promise) {
      if (!(this instanceof __Facade_ExtendableEvent__)) {
        throw new TypeError("Illegal invocation");
      }
      this[__facade_waitUntil__].push(promise);
    }
  };
  __name(__Facade_ExtendableEvent__, "__Facade_ExtendableEvent__");
  var __Facade_FetchEvent__ = class extends __Facade_ExtendableEvent__ {
    #request;
    #passThroughOnException;
    [__facade_response__];
    [__facade_dispatched__] = false;
    constructor(type, init) {
      super(type);
      this.#request = init.request;
      this.#passThroughOnException = init.passThroughOnException;
    }
    get request() {
      return this.#request;
    }
    respondWith(response) {
      if (!(this instanceof __Facade_FetchEvent__)) {
        throw new TypeError("Illegal invocation");
      }
      if (this[__facade_response__] !== void 0) {
        throw new DOMException(
          "FetchEvent.respondWith() has already been called; it can only be called once.",
          "InvalidStateError"
        );
      }
      if (this[__facade_dispatched__]) {
        throw new DOMException(
          "Too late to call FetchEvent.respondWith(). It must be called synchronously in the event handler.",
          "InvalidStateError"
        );
      }
      this.stopImmediatePropagation();
      this[__facade_response__] = response;
    }
    passThroughOnException() {
      if (!(this instanceof __Facade_FetchEvent__)) {
        throw new TypeError("Illegal invocation");
      }
      this.#passThroughOnException();
    }
  };
  __name(__Facade_FetchEvent__, "__Facade_FetchEvent__");
  var __Facade_ScheduledEvent__ = class extends __Facade_ExtendableEvent__ {
    #scheduledTime;
    #cron;
    #noRetry;
    constructor(type, init) {
      super(type);
      this.#scheduledTime = init.scheduledTime;
      this.#cron = init.cron;
      this.#noRetry = init.noRetry;
    }
    get scheduledTime() {
      return this.#scheduledTime;
    }
    get cron() {
      return this.#cron;
    }
    noRetry() {
      if (!(this instanceof __Facade_ScheduledEvent__)) {
        throw new TypeError("Illegal invocation");
      }
      this.#noRetry();
    }
  };
  __name(__Facade_ScheduledEvent__, "__Facade_ScheduledEvent__");
  __facade__originalAddEventListener__("fetch", (event) => {
    const ctx = {
      waitUntil: event.waitUntil.bind(event),
      passThroughOnException: event.passThroughOnException.bind(event)
    };
    const __facade_sw_dispatch__ = /* @__PURE__ */ __name(function(type, init) {
      if (type === "scheduled") {
        const facadeEvent = new __Facade_ScheduledEvent__("scheduled", {
          scheduledTime: Date.now(),
          cron: init.cron ?? "",
          noRetry() {
          }
        });
        __FACADE_EVENT_TARGET__.dispatchEvent(facadeEvent);
        event.waitUntil(Promise.all(facadeEvent[__facade_waitUntil__]));
      }
    }, "__facade_sw_dispatch__");
    const __facade_sw_fetch__ = /* @__PURE__ */ __name(function(request, _env, ctx2) {
      const facadeEvent = new __Facade_FetchEvent__("fetch", {
        request,
        passThroughOnException: ctx2.passThroughOnException
      });
      __FACADE_EVENT_TARGET__.dispatchEvent(facadeEvent);
      facadeEvent[__facade_dispatched__] = true;
      event.waitUntil(Promise.all(facadeEvent[__facade_waitUntil__]));
      const response = facadeEvent[__facade_response__];
      if (response === void 0) {
        throw new Error("No response!");
      }
      return response;
    }, "__facade_sw_fetch__");
    event.respondWith(
      __facade_invoke__(
        event.request,
        globalThis,
        ctx,
        __facade_sw_dispatch__,
        __facade_sw_fetch__
      )
    );
  });
  __facade__originalAddEventListener__("scheduled", (event) => {
    const facadeEvent = new __Facade_ScheduledEvent__("scheduled", {
      scheduledTime: event.scheduledTime,
      cron: event.cron,
      noRetry: event.noRetry.bind(event)
    });
    __FACADE_EVENT_TARGET__.dispatchEvent(facadeEvent);
    event.waitUntil(Promise.all(facadeEvent[__facade_waitUntil__]));
  });

  // ../../node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
  var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
    try {
      return await middlewareCtx.next(request, env);
    } finally {
      try {
        if (request.body !== null && !request.bodyUsed) {
          const reader = request.body.getReader();
          while (!(await reader.read()).done) {
          }
        }
      } catch (e) {
        console.error("Failed to drain the unused request body.", e);
      }
    }
  }, "drainBody");
  var middleware_ensure_req_body_drained_default = drainBody;

  // ../../node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
  function reduceError(e) {
    return {
      name: e?.name,
      message: e?.message ?? String(e),
      stack: e?.stack,
      cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
    };
  }
  __name(reduceError, "reduceError");
  var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
    try {
      return await middlewareCtx.next(request, env);
    } catch (e) {
      const error = reduceError(e);
      return Response.json(error, {
        status: 500,
        headers: { "MF-Experimental-Error-Stack": "true" }
      });
    }
  }, "jsonError");
  var middleware_miniflare3_json_error_default = jsonError;

  // .wrangler/tmp/bundle-KY8Inb/middleware-insertion-facade.js
  __facade_registerInternal__([middleware_ensure_req_body_drained_default, middleware_miniflare3_json_error_default]);

  // cf-worker.js
  addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event.request));
  });
  var STORED_TRANSACTION_ID = new Uint8Array([4, 210]);
  async function handleRequest(request) {
    const rawBody = await request.arrayBuffer();
    const dnsQueryBuffer = new Uint8Array(rawBody);
    try {
      const transaction_id = extractTransactionId(dnsQueryBuffer);
      const domain = extractDomainNameFromQuery(dnsQueryBuffer);
      const isMatch = compareTransactionId(transaction_id, STORED_TRANSACTION_ID);
      if (!isMatch) {
        return createNxDnsResponse(domain, transaction_id);
      }
      const response = await fetch("http://127.0.0.1:5000/1234");
      const ipv6List = await response.json();
      return createAnswerDnsResponse(domain, transaction_id, ipv6List);
    } catch (error) {
      return new Response({ status: 500 });
    }
  }
  __name(handleRequest, "handleRequest");
  function createNxDnsResponse(domain, transactionId) {
    const qr = 1;
    const opcode = 2;
    const aa = 0;
    const tc = 0;
    const rd = 1;
    const flags1 = qr << 7 | opcode << 3 | aa << 2 | tc << 1 | rd;
    const ra = 1;
    const z = 0;
    const ad = 0;
    const cd = 0;
    const rcode = 3;
    const flags2 = ra << 7 | z << 6 | ad << 5 | cd << 4 | rcode;
    const flags = new Uint8Array([flags1, flags2]);
    const qdcount = new Uint8Array([0, 1]);
    const ancount = new Uint8Array([0, 0]);
    const nscount = new Uint8Array([0, 0]);
    const arcount = new Uint8Array([0, 0]);
    const encodedDomain = encodeDomainName(domain);
    const question = new Uint8Array([
      ...encodedDomain,
      // Encoded domain name
      0,
      1,
      // Type A (0x0001)
      0,
      1
      // Class IN (0x0001)
    ]);
    const response = new Uint8Array([
      ...transactionId,
      ...flags,
      ...qdcount,
      ...ancount,
      ...nscount,
      ...arcount,
      ...question
    ]);
    return new Response(response.buffer, {
      headers: { "Content-Type": "application/dns-message" }
    });
  }
  __name(createNxDnsResponse, "createNxDnsResponse");
  function createAnswerDnsResponse(domain, transaction_id, ipv6List) {
    const qr = 1;
    const opcode = 0;
    const aa = 1;
    const tc = 0;
    const rd = 1;
    const flags1 = qr << 7 | opcode << 3 | aa << 2 | tc << 1 | rd;
    const ra = 1;
    const z = 0;
    const ad = 1;
    const cd = 0;
    const rcode = 0;
    const flags2 = ra << 7 | z << 6 | ad << 5 | cd << 4 | rcode;
    const flags = new Uint8Array([flags1, flags2]);
    const qdcount = new Uint8Array([0, 1]);
    const ancount = new Uint8Array([0, 1]);
    const nscount = new Uint8Array([0, 0]);
    const arcount = new Uint8Array([0, 0]);
    const encodedDomain = encodeDomainName(domain);
    const question = new Uint8Array([
      ...encodedDomain,
      // Encoded domain name
      0,
      28,
      // Type AAAA (IPv6)
      0,
      1
      // Class IN (0x0001)
    ]);
    const answers = ipv6List.map((ipv6) => {
      const ipv6Bytes = expandAndConvertIPv6(ipv6);
      const rdLength = new Uint8Array([0, 16]);
      return new Uint8Array([
        ...encodedDomain,
        // Domain name
        0,
        28,
        // Type AAAA
        0,
        1,
        // Class IN
        0,
        0,
        0,
        60,
        // TTL (60 seconds)
        ...rdLength,
        // Length of data (16 bytes for IPv6)
        ...ipv6Bytes
        // Expanded IPv6 address bytes
      ]);
    });
    const response = new Uint8Array([
      ...transaction_id,
      // Transaction ID (must be 2 bytes)
      ...flags,
      // Flags
      ...qdcount,
      // Question count
      ...ancount,
      // Answer count
      ...nscount,
      // Authority count
      ...arcount,
      // Additional record count
      ...question,
      // Question section
      ...answers.flat()
      // Flatten answers and append
    ]);
    return new Response(response.buffer, {
      headers: { "Content-Type": "application/dns-message" }
    });
  }
  __name(createAnswerDnsResponse, "createAnswerDnsResponse");
  function expandAndConvertIPv6(ipv6) {
    const expanded = ipv6.split("::").map((part) => {
      return part ? part.split(":") : [];
    });
    const parts = expanded[0].concat(expanded[1] || []).map((part) => {
      return part.length === 1 ? `00${part}` : part.length === 2 ? `0${part}` : part;
    });
    while (parts.length < 8) {
      parts.push("0000");
    }
    return parts.flatMap((part) => {
      const highByte = parseInt(part.substring(0, 2), 16);
      const lowByte = parseInt(part.substring(2, 4), 16);
      return [highByte, lowByte];
    });
  }
  __name(expandAndConvertIPv6, "expandAndConvertIPv6");
  function extractTransactionId(queryBuffer) {
    const transactionId = queryBuffer.slice(0, 2);
    return transactionId;
  }
  __name(extractTransactionId, "extractTransactionId");
  function extractDomainNameFromQuery(queryBuffer) {
    let offset = 12;
    const domainParts = [];
    while (true) {
      const labelLength = queryBuffer[offset];
      if (labelLength === 0)
        break;
      const label = String.fromCharCode(...queryBuffer.slice(offset + 1, offset + 1 + labelLength));
      domainParts.push(label);
      offset += labelLength + 1;
    }
    const domain = domainParts.join(".");
    return domain;
  }
  __name(extractDomainNameFromQuery, "extractDomainNameFromQuery");
  function compareTransactionId(transactionId, storedTransactionId) {
    if (transactionId.length !== storedTransactionId.length) {
      return false;
    }
    for (let i = 0; i < transactionId.length; i++) {
      if (transactionId[i] !== storedTransactionId[i]) {
        return false;
      }
    }
    return true;
  }
  __name(compareTransactionId, "compareTransactionId");
  function encodeDomainName(domain) {
    const parts = domain.split(".");
    const labels = [];
    for (const part of parts) {
      const length = part.length;
      labels.push(length);
      for (let i = 0; i < length; i++) {
        labels.push(part.charCodeAt(i));
      }
    }
    labels.push(0);
    return labels;
  }
  __name(encodeDomainName, "encodeDomainName");
})();
//# sourceMappingURL=cf-worker.js.map
