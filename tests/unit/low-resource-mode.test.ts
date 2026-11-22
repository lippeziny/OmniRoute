import test from "node:test";
import assert from "node:assert/strict";

import {
  isBackgroundServicesDisabled,
  isLowResourceMode,
} from "../../src/lib/env/backgroundServices.ts";
import { isHeadless } from "../../src/lib/system/headless.ts";

test("low-resource mode accepts the supported truthy spellings", () => {
  for (const value of ["1", "true", "TRUE", "yes", "On"]) {
    assert.equal(isLowResourceMode({ OMNIROUTE_LOW_RESOURCE_MODE: value }), true, value);
  }
});

test("low-resource mode is disabled when unset or false", () => {
  for (const value of [undefined, "", "0", "false", "no", "off"]) {
    assert.equal(
      isLowResourceMode({ OMNIROUTE_LOW_RESOURCE_MODE: value }),
      false,
      String(value)
    );
  }
});

test("low-resource mode does not disable dashboard or global background-service state", () => {
  const env = {
    OMNIROUTE_LOW_RESOURCE_MODE: "1",
    OMNIROUTE_HEADLESS: "0",
    OMNIROUTE_DISABLE_BACKGROUND_SERVICES: "0",
  };
  assert.equal(isLowResourceMode(env), true);
  assert.equal(isHeadless(env), false);
  assert.equal(isBackgroundServicesDisabled(env), false);
});
