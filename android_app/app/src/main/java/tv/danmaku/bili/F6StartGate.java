package tv.danmaku.bili;

/** A granted Shizuku permission must not silently downgrade a pending shell connection to app I/O. */
final class F6StartGate {
    enum Decision { APP, SHIZUKU, WAIT_FOR_SHIZUKU, SHIZUKU_NOT_RUNNING, SHIZUKU_PERMISSION_REQUIRED }
    static Decision choose(int channel, boolean running, boolean authorized, boolean serviceConnected) {
        if (channel == 1) return Decision.APP;
        if (channel == 2 && !running) return Decision.SHIZUKU_NOT_RUNNING;
        if (channel == 2 && !authorized) return Decision.SHIZUKU_PERMISSION_REQUIRED;
        if (running && authorized) return serviceConnected ? Decision.SHIZUKU : Decision.WAIT_FOR_SHIZUKU;
        return Decision.APP;
    }
}
