// The device tests and the Node run drive the same in-memory Flow ID the package ships for plugins.
export {
  adminBrowser,
  fakeFlowId,
  memoryStore as memory,
  TEST_DID as did,
  TEST_HOST as host,
  TEST_VAULT_URI as uri,
} from "../src/testing/index.ts";
