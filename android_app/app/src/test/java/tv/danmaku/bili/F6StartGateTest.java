package tv.danmaku.bili;

import org.junit.Test;
import static org.junit.Assert.*;

public class F6StartGateTest {
    @Test public void permissionAloneWaitsForServiceInsteadOfDowngrading() {
        assertEquals(F6StartGate.Decision.WAIT_FOR_SHIZUKU, F6StartGate.choose(0, true, true, false));
        assertEquals(F6StartGate.Decision.WAIT_FOR_SHIZUKU, F6StartGate.choose(2, true, true, false));
    }
    @Test public void connectedAuthorizedServiceEnablesPrivilegedScan() {
        assertEquals(F6StartGate.Decision.SHIZUKU, F6StartGate.choose(0, true, true, true));
        assertEquals(F6StartGate.Decision.SHIZUKU, F6StartGate.choose(2, true, true, true));
    }
    @Test public void ordinaryAppChoiceRemainsExplicitEvenWithShizuku() {
        assertEquals(F6StartGate.Decision.APP, F6StartGate.choose(1, true, true, true));
    }
    @Test public void explicitShizukuCannotRunWithoutPrerequisites() {
        assertEquals(F6StartGate.Decision.SHIZUKU_NOT_RUNNING, F6StartGate.choose(2, false, false, false));
        assertEquals(F6StartGate.Decision.SHIZUKU_PERMISSION_REQUIRED, F6StartGate.choose(2, true, false, false));
    }
    @Test public void autoChoiceUsesOrdinaryAppIfShizukuIsUnavailable() {
        assertEquals(F6StartGate.Decision.APP, F6StartGate.choose(0, false, false, false));
        assertEquals(F6StartGate.Decision.APP, F6StartGate.choose(0, true, false, false));
    }
}
