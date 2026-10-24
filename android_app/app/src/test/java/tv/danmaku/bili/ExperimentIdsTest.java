package tv.danmaku.bili;

import org.junit.Test;
import static org.junit.Assert.*;

public class ExperimentIdsTest {
    @Test public void generatedLocalExperimentWorksWithoutServerSetup() {
        String a = ExperimentIds.local(), b = ExperimentIds.local();
        assertTrue(a.startsWith("local-")); assertTrue(ExperimentIds.valid(a)); assertNotEquals(a, b);
    }
    @Test public void serverRunIdentifiersRemainValid() {
        assertTrue(ExperimentIds.valid("trial-01")); assertTrue(ExperimentIds.valid("session.1_test"));
    }
    @Test public void invalidIdentifiersCannotBeRelabelledAsAValidRun() {
        for (String id : new String[]{null, "", "../other", " leading-space", "中文", new String(new char[97]).replace('\0', 'a')}) assertFalse(ExperimentIds.valid(id));
    }
}
