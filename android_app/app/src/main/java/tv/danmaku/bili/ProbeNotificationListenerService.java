package tv.danmaku.bili;

import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

/** Receives no notification data: callbacks are deliberately empty; telemetry reports access state only. */
public final class ProbeNotificationListenerService extends NotificationListenerService {
    @Override public void onNotificationPosted(StatusBarNotification notification) { }
    @Override public void onNotificationRemoved(StatusBarNotification notification) { }
}
