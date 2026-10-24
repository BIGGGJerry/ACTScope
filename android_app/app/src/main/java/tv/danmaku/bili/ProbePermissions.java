package tv.danmaku.bili;

import android.app.NotificationManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import org.json.JSONObject;

/** Reads only the enabled/disabled states needed by F5/F7 telemetry. */
final class ProbePermissions {
    private ProbePermissions() { }

    static ComponentName deviceAdminComponent(Context context) {
        return new ComponentName(context, ProbeDeviceAdminReceiver.class);
    }

    static ComponentName notificationListenerComponent(Context context) {
        return new ComponentName(context, ProbeNotificationListenerService.class);
    }

    static Object deviceAdminEnabled(Context context) {
        try {
            DevicePolicyManager manager = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
            return manager == null ? JSONObject.NULL : manager.isAdminActive(deviceAdminComponent(context));
        } catch (RuntimeException e) { return JSONObject.NULL; }
    }

    static Object notificationListenerEnabled(Context context) {
        try {
            ComponentName component = notificationListenerComponent(context);
            if (Build.VERSION.SDK_INT >= 27) {
                NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
                return manager == null ? JSONObject.NULL : manager.isNotificationListenerAccessGranted(component);
            }
            String enabled = Settings.Secure.getString(context.getContentResolver(), "enabled_notification_listeners");
            if (enabled == null || enabled.isEmpty()) return false;
            for (String item : enabled.split(":")) if (component.equals(ComponentName.unflattenFromString(item))) return true;
            return false;
        } catch (RuntimeException e) { return JSONObject.NULL; }
    }
}
