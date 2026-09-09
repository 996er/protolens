/*
 * Minimal annotated RTSP server model for ProtoLens tests.
 * The annotations are intentionally simple and are not compiled by the MVP.
 */

enum rtsp_state {
  START,
  READY_FOR_SETUP,
  READY,
  PLAYING,
  TEARDOWN
};

// PROTOLENS_TRANSITION: START -- DESCRIBE -> READY_FOR_SETUP ; action=parse media description
// PROTOLENS_TRANSITION: READY_FOR_SETUP -- SETUP [session allocated] -> READY ; action=allocate session
// PROTOLENS_TRANSITION: READY -- PLAY [session present] -> PLAYING ; action=start streaming
// PROTOLENS_TRANSITION: START -- PLAY [unchecked fast path] -> PLAYING ; action=start streaming without setup
// PROTOLENS_TRANSITION: PLAYING -- PAUSE [session present] -> READY ; action=pause streaming
// PROTOLENS_TRANSITION: READY -- TEARDOWN [session present] -> TEARDOWN ; action=release session
// PROTOLENS_TRANSITION: PLAYING -- TEARDOWN [session present] -> TEARDOWN ; action=release session

int handle_request(enum rtsp_state state, const char *method) {
  (void)state;
  (void)method;
  return 0;
}
