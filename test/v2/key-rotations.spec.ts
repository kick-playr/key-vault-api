import { assertActivationReady } from "../../src/v2/key-rotations.js";
it("never ages an offline participant out of the activation barrier", () => {
  expect(() =>
    assertActivationReady(
      [
        {
          instanceId: "offline",
          acknowledged: false,
          retired: false,
          lastSeen: 0,
        },
      ],
      Date.now(),
    ),
  ).toThrow();
  expect(() =>
    assertActivationReady(
      [
        {
          instanceId: "online",
          acknowledged: true,
          retired: false,
          lastSeen: 0,
        },
      ],
      Date.now(),
    ),
  ).not.toThrow();
  expect(() =>
    assertActivationReady(
      [
        {
          instanceId: "stopped",
          acknowledged: false,
          retired: true,
          lastSeen: 0,
        },
      ],
      Date.now(),
    ),
  ).not.toThrow();
});
